'use strict';

setImmediate(function () {
  Java.perform(function () {
    try {
      const Builder = Java.use('okhttp3.CertificatePinner$Builder');
      const add = Builder.add.overload('java.lang.String', '[Ljava.lang.String;');
      add.implementation = function (pattern, pins) {
        send({
          event: 'certificate_pin_registered',
          framework: 'okhttp3',
          pattern: pattern,
          pinCount: pins.length
        });
        return add.call(this, pattern, pins);
      };
      send({ event: 'script_loaded', script: 'observe-tls-trust' });
    } catch (error) {
      send({ event: 'framework_not_found', framework: 'okhttp3', error: String(error) });
    }
  });
});

