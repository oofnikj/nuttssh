# Nuttssh - Copyright Matthijs Kooijman <matthijs@stdin.nl>
#
# This file is made available under the MIT license. See the accompanying
# LICENSE file for the full text.

import sys
import signal
import asyncio
import logging

from . import server


async def shutdown(signal, loop):
    logging.error(f"Received signal {signal.name}, shutting down")
    tasks = [task for task in asyncio.all_tasks()
        if task is not asyncio.current_task()]
    
    for task in tasks:
        logging.debug("Cancelling task %s" % task)
        task.cancel()
    
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()

def main():
    logging.basicConfig(level=logging.DEBUG)

    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT)
    loop = asyncio.get_event_loop()
    for s in signals:
        loop.add_signal_handler(
            s, lambda s=s: asyncio.create_task(shutdown(s, loop))
        )
    try:
        daemon = server.NuttsshDaemon()
        loop.create_task(daemon.start())
        loop.run_forever()

    except Exception as exc:
        sys.exit('Error starting server: ' + str(exc))
    finally:
        loop.close()

main()