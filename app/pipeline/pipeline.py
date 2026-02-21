"""
Async Queue-based pipeline orchestrator (TO-BE architecture).

Collector -> Queue -> Normalizer -> Queue -> Enricher -> Queue -> Scorer
    -> Queue -> Aggregator -> Queue -> Correlator -> Queue -> IncidentManager

Each stage is an independent async worker consuming from an input queue
and producing to an output queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from app.config import (
    RAW_DIR,
    NORMALIZED_DIR,
    PIPELINE_QUEUE_SIZE,
)
from app.pipeline.normalize import normalize
from app.pipeline.enrich import enrich_dict
from app.pipeline.scoring import score
from app.pipeline.aggregate import update_aggregate
from app.pipeline.correlate import run_correlation
from app.services.alerts_store import add_alert
from app.services.events_store import add_event

logger = logging.getLogger("siem.pipeline")


class Pipeline:
    """Async Queue-based SIEM pipeline."""

    def __init__(self, queue_size: int = PIPELINE_QUEUE_SIZE):
        self.q_raw = asyncio.Queue(maxsize=queue_size)
        self.q_normalized = asyncio.Queue(maxsize=queue_size)
        self.q_enriched = asyncio.Queue(maxsize=queue_size)
        self.q_scored = asyncio.Queue(maxsize=queue_size)
        self.q_aggregated = asyncio.Queue(maxsize=queue_size)
        self.q_correlated = asyncio.Queue(maxsize=queue_size)

        self._workers: list[asyncio.Task] = []
        self._running = False

    async def start(self) -> None:
        """Start all pipeline stage workers."""
        if self._running:
            return
        self._running = True
        self._workers = [
            asyncio.create_task(self._stage_normalizer(), name="normalizer"),
            asyncio.create_task(self._stage_enricher(), name="enricher"),
            asyncio.create_task(self._stage_scorer(), name="scorer"),
            asyncio.create_task(self._stage_aggregator(), name="aggregator"),
            asyncio.create_task(self._stage_correlator(), name="correlator"),
            asyncio.create_task(self._stage_incident_manager(), name="incident_manager"),
        ]
        logger.info("[PIPELINE] Started %d stage workers", len(self._workers))

    async def stop(self) -> None:
        """Gracefully stop all pipeline workers."""
        self._running = False
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            try:
                await w
            except asyncio.CancelledError:
                pass
        self._workers.clear()
        logger.info("[PIPELINE] All workers stopped")

    async def push_raw(self, payload: dict) -> dict:
        """Collector stage: store raw event and push to normalizer queue.

        Returns basic result dict with raw_id.
        """
        RAW_DIR.mkdir(parents=True, exist_ok=True)
        NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

        raw_id = str(uuid4())
        received_at = datetime.now(timezone.utc).isoformat()

        record = {
            "raw_id": raw_id,
            "received_at": received_at,
            "payload": payload,
        }

        # 1) Persist raw event (forensic archive)
        out_path = RAW_DIR / f"{raw_id}.json"
        out_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # Push to normalizer queue
        await self.q_raw.put(record)

        logger.info(
            "[COLLECTOR] raw_id=%s source=%s pushed to pipeline",
            raw_id,
            payload.get("source_type", "?"),
        )

        return {
            "raw_id": raw_id,
            "stored_to": str(out_path),
            "status": "queued",
        }

    # ------------------------------------------------------------------
    # Stage workers
    # ------------------------------------------------------------------

    async def _stage_normalizer(self) -> None:
        """Consume raw records, normalize, push to enricher queue."""
        while self._running:
            try:
                record = await asyncio.wait_for(self.q_raw.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                payload = record["payload"]
                raw_id = record["raw_id"]
                received_at_iso = record["received_at"]

                normalized = normalize(
                    payload=payload,
                    raw_id=raw_id,
                    received_at_iso=received_at_iso,
                )
                normalized_dict = normalized.model_dump(mode="json")
                normalized_dict["_raw_record"] = record

                await self.q_normalized.put(normalized_dict)
                logger.debug("[NORMALIZER] raw_id=%s -> normalized", raw_id)
            except Exception:
                logger.exception("[NORMALIZER] Error processing raw_id=%s", record.get("raw_id"))
            finally:
                self.q_raw.task_done()

    async def _stage_enricher(self) -> None:
        """Consume normalized events, enrich with CMDB/IOC, push to scorer."""
        while self._running:
            try:
                normalized_dict = await asyncio.wait_for(self.q_normalized.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                enriched = enrich_dict(normalized_dict)
                await self.q_enriched.put(enriched)
                logger.debug("[ENRICHER] event_id=%s enriched", enriched.get("event_id"))
            except Exception:
                logger.exception("[ENRICHER] Error")
            finally:
                self.q_normalized.task_done()

    async def _stage_scorer(self) -> None:
        """Consume enriched events, compute risk score, push to aggregator."""
        while self._running:
            try:
                enriched = await asyncio.wait_for(self.q_enriched.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                risk, priority, is_critical = score(enriched)
                enriched["risk"] = risk
                enriched["priority"] = priority
                enriched["_is_critical"] = is_critical

                await self.q_scored.put(enriched)
                logger.debug(
                    "[SCORER] event_id=%s risk=%.2f priority=%s",
                    enriched.get("event_id"),
                    risk,
                    priority,
                )
            except Exception:
                logger.exception("[SCORER] Error")
            finally:
                self.q_enriched.task_done()

    async def _stage_aggregator(self) -> None:
        """Consume scored events, update aggregates, push to correlator."""
        while self._running:
            try:
                scored = await asyncio.wait_for(self.q_scored.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                update_aggregate(scored)
                add_event(scored)

                # Persist normalized event to disk
                raw_id = scored.get("raw_event_id") or scored.get("event_id")
                if raw_id:
                    normalized_path = NORMALIZED_DIR / f"{raw_id}.json"
                    normalized_path.write_text(
                        json.dumps(scored, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8",
                    )

                await self.q_aggregated.put(scored)
                logger.debug("[AGGREGATOR] event_id=%s aggregated", scored.get("event_id"))
            except Exception:
                logger.exception("[AGGREGATOR] Error")
            finally:
                self.q_scored.task_done()

    async def _stage_correlator(self) -> None:
        """Consume aggregated events, generate alerts for critical ones, push to incident manager."""
        while self._running:
            try:
                event = await asyncio.wait_for(self.q_aggregated.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                is_critical = event.pop("_is_critical", False)
                raw_record = event.pop("_raw_record", {})
                payload = raw_record.get("payload", {})

                # Critical events -> alerts feed
                if is_critical:
                    raw_id = event.get("raw_event_id") or event.get("event_id")
                    add_alert({
                        "alert_id": f"AL-{uuid4().hex[:12].upper()}",
                        "raw_id": raw_id,
                        "priority": event.get("priority"),
                        "risk": event.get("risk"),
                        "source_type": event.get("source_type") or payload.get("source_type"),
                        "format": event.get("format") or payload.get("format"),
                        "received_at": event.get("received_at"),
                        "event_type": event.get("event_type"),
                        "src_ip": event.get("src_ip"),
                        "dst_ip": event.get("dst_ip"),
                        "user": event.get("user"),
                        "snippet": str(payload.get("data", ""))[:200],
                    })

                await self.q_correlated.put(event)
                logger.debug("[CORRELATOR] event queued for incident check")
            except Exception:
                logger.exception("[CORRELATOR] Error")
            finally:
                self.q_aggregated.task_done()

    async def _stage_incident_manager(self) -> None:
        """Consume correlated events, run correlation rules, create incidents."""
        while self._running:
            try:
                event = await asyncio.wait_for(self.q_correlated.get(), timeout=1.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                continue

            try:
                incidents = run_correlation()
                if incidents:
                    logger.info(
                        "[INCIDENT_MANAGER] %d incidents created for event_id=%s",
                        len(incidents),
                        event.get("event_id"),
                    )

                raw_id = event.get("raw_event_id") or event.get("event_id")
                print(
                    f"[PIPELINE] raw_id={raw_id} "
                    f"type={event.get('event_type')} "
                    f"src={event.get('src_ip')} "
                    f"user={event.get('user')} "
                    f"risk={event.get('risk')} priority={event.get('priority')}"
                )
                if incidents:
                    print(f"[CORRELATION] incidents={incidents}")
            except Exception:
                logger.exception("[INCIDENT_MANAGER] Error")
            finally:
                self.q_correlated.task_done()


# Singleton pipeline instance
_pipeline: Optional[Pipeline] = None


def get_pipeline() -> Pipeline:
    """Get or create the singleton pipeline instance."""
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline()
    return _pipeline
