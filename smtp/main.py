"""
Sender Safety SMTP server.
Sprint 1 stub — starts aiosmtpd, logs incoming connections, does nothing else yet.
Full scan/forward logic comes in Sprint 2.
"""
import asyncio
import logging
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Debugging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


class StubHandler:
    async def handle_RCPT(
        self, server, session, envelope, address: str, rcpt_options: list
    ) -> str:
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        logger.info(
            "Received email: from=%s to=%s size=%d bytes",
            envelope.mail_from,
            envelope.rcpt_tos,
            len(envelope.content),
        )
        # Sprint 2: scan and forward/reject here
        return "250 Message accepted for delivery (stub)"


if __name__ == "__main__":
    handler = StubHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=587)
    controller.start()
    logger.info("SMTP stub server listening on port 587")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        controller.stop()
