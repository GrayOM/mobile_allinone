'use strict';

setImmediate(function () {
  Java.perform(function () {
    const File = Java.use('java.io.File');
    const originalExists = File.exists.overload();
    const watched = ['/system/bin/su', '/system/xbin/su', '/sbin/magisk'];
    originalExists.implementation = function () {
      const path = this.getAbsolutePath();
      const result = originalExists.call(this);
      if (watched.indexOf(path) !== -1) {
        send({
          event: 'root_check',
          api: 'java.io.File.exists',
          path: path,
          originalResult: result
        });
      }
      return result;
    };
    send({ event: 'script_loaded', script: 'observe-root-signals' });
  });
});

