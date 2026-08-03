'use strict';

setImmediate(function () {
  const fileExists = Module.findExportByName(null, 'access');
  if (fileExists) {
    Interceptor.attach(fileExists, {
      onEnter(args) {
        this.path = args[0].readUtf8String();
      },
      onLeave(retval) {
        if (this.path && /Cydia|MobileSubstrate|\/bin\/bash/.test(this.path)) {
          send({ event: 'jailbreak_path_check', path: this.path, result: retval.toInt32() });
        }
      }
    });
  }
  send({ event: 'script_loaded', script: 'observe-jailbreak-signals' });
});

