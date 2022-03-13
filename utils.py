from functools import wraps
import inspect
import signal

def log(logger):

   def decorator(fn):

      @wraps(fn)
      def wrapper(*args, **kwargs):
         sig = inspect.signature(fn)
         ba = sig.bind(*args, **kwargs)
         ba.apply_defaults()
         caller = inspect.stack()[1]
         logger.info(f"{fn.__name__} called in {caller.filename}:{caller.lineno} with: {ba.arguments}")
         result = fn(*args, **kwargs)
         logger.info(f"{fn.__name__} returned: {result}")

         return result

      return wrapper

   return decorator

class GracefulSocketKiller:
   kill_now = False
   def __init__(self, socket):
      self.socket = socket
      signal.signal(signal.SIGINT, self.exit_gracefully)
      signal.signal(signal.SIGTERM, self.exit_gracefully)

   def exit_gracefully(self, *args):
      self.kill_now = True
      self.socket.close()