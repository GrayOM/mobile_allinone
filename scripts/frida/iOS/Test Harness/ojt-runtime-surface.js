'use strict';

function mswReport(payload) {
  send(Object.assign({
    event: 'ojt_runtime_surface',
    control: 'authorized_runtime_observation',
    run_marker: 'a5f47c17'
  }, payload));
}

function mswMain() {
  if (!ObjC.available) {
    mswReport({ status: 'failed', reason: 'objc_runtime_unavailable' });
    return;
  }

  try {
    const appClasses = Object.keys(ObjC.classes)
      .filter(function (name) {
        return name.indexOf('_TtC3ojt') === 0 || name.indexOf('ojt.') === 0;
      })
      .sort()
      .slice(0, 100);

    const classes = appClasses.map(function (name) {
      const wrapper = ObjC.classes[name];
      return {
        name: name,
        own_methods: (wrapper.$ownMethods || []).map(String).sort().slice(0, 100)
      };
    });

    const targetNames = [
      '_TtC3ojt15DatabaseManager',
      '_TtC3ojt15PinRegistration',
      '_TtC3ojt6Bioreg',
      '_TtC3ojt7Pinauth',
      '_TtC3ojt7Bioauth'
    ];
    const liveInstances = targetNames.map(function (name) {
      const wrapper = ObjC.classes[name];
      if (!wrapper) return { name: name, available: false, instance_count: 0 };
      let count = 0;
      try { count = ObjC.chooseSync(wrapper).length; } catch (_) {}
      return { name: name, available: true, instance_count: count };
    });

    mswReport({
      status: 'completed',
      class_count: classes.length,
      classes: classes,
      live_instances: liveInstances
    });
  } catch (error) {
    mswReport({ status: 'failed', reason: 'exception', error: String(error) });
  }
}

setTimeout(mswMain, 250);
