'use strict';

setImmediate(function () {
  Java.perform(function () {
    const Debug = Java.use('android.os.Debug');
    const original = Debug.isDebuggerConnected.overload();
    original.implementation = function () {
      const result = original.call(this);
      send({ event: 'debugger_check', originalResult: result });
      return result;
    };
    send({ event: 'script_loaded', script: 'observe-debug-checks' });
  });
});

