'use strict';

const MSW_ROOT_PATHS = [
  '/system/bin/su',
  '/system/xbin/su',
  '/sbin/su',
  '/sbin/magisk',
  '/data/adb/magisk',
  '/data/adb/modules',
  '/system/app/Superuser.apk',
  '/system/app/SuperSU.apk',
  '/system/xbin/daemonsu',
  '/system/bin/.ext/.su',
  '/cache/su',
  '/data/local/su',
  '/data/local/bin/su',
  '/data/local/xbin/su'
];

const MSW_ROOT_PACKAGES = [
  'com.topjohnwu.magisk',
  'eu.chainfire.supersu',
  'com.noshufou.android.su',
  'com.koushikdutta.superuser',
  'com.thirdparty.superuser',
  'com.yellowes.su',
  'com.kingroot.kinguser',
  'com.kingo.root',
  'com.smedialink.oneclickroot'
];

let mswEventCount = 0;

function mswReport(api, value) {
  if (mswEventCount >= 200) return;
  mswEventCount += 1;
  send({
    event: 'security_control_bypass',
    control: 'root_detection',
    api: api,
    value: String(value),
    action: 'masked',
    sequence: mswEventCount
  });
}

function mswLooksLikeRootPath(value) {
  if (!value) return false;
  const path = String(value).toLowerCase();
  return MSW_ROOT_PATHS.some(function (item) {
    return path === item || path.indexOf(item + '/') === 0;
  }) || /(^|\/)(magisk|supersu|superuser|daemonsu)(\/|$)/i.test(path);
}

function mswLooksLikeRootPackage(value) {
  const name = String(value || '').toLowerCase();
  return MSW_ROOT_PACKAGES.indexOf(name) !== -1;
}

function mswCommandText(value) {
  if (value === null || value === undefined) return '';
  try {
    if (value.$className === '[Ljava.lang.String;') {
      const items = [];
      for (let index = 0; index < value.length; index += 1) {
        items.push(String(value[index]));
      }
      return items.join(' ');
    }
  } catch (_) {
    // Fall back to the Java string representation below.
  }
  return String(value);
}

function mswLooksLikeRootProbe(value) {
  const command = mswCommandText(value)
    .trim()
    .toLowerCase()
    .replace(/[\[\],]/g, ' ')
    .replace(/\s+/g, ' ');
  return /(^|\s|\/)(su|magisk|busybox)(\s|$)/.test(command)
    || /(^|\s)which\s+su(\s|$)/.test(command)
    || /(^|\s)getprop\s+(ro\.secure|ro\.debuggable|ro\.build\.tags)/.test(command)
    || /(^|\s)(mount|id)(\s|$)/.test(command);
}

function mswReadCString(pointer) {
  try {
    return pointer.isNull() ? '' : pointer.readUtf8String();
  } catch (_) {
    return '';
  }
}

function mswHookNativePath(api) {
  const address = Module.findExportByName(null, api);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.mswPath = mswReadCString(args[0]);
      this.mswMask = mswLooksLikeRootPath(this.mswPath);
    },
    onLeave(retval) {
      if (!this.mswMask) return;
      mswReport('libc.' + api, this.mswPath);
      retval.replace(-1);
    }
  });
}

function mswHookNativeOpen(api, pointerResult) {
  const address = Module.findExportByName(null, api);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.mswPath = mswReadCString(args[0]);
      this.mswMask = mswLooksLikeRootPath(this.mswPath);
    },
    onLeave(retval) {
      if (!this.mswMask) return;
      mswReport('libc.' + api, this.mswPath);
      retval.replace(pointerResult ? ptr(0) : -1);
    }
  });
}

function mswHookBooleanMethods(className, methodNames) {
  try {
    const Target = Java.use(className);
    methodNames.forEach(function (methodName) {
      if (!Target[methodName]) return;
      Target[methodName].overloads.forEach(function (overload) {
        if (overload.returnType.className !== 'boolean') return;
        overload.implementation = function () {
          mswReport(className + '.' + methodName, 'true');
          return false;
        };
      });
    });
  } catch (_) {
    // Optional third-party detector is not present in this application.
  }
}

setImmediate(function () {
  ['access', 'stat', 'lstat', 'stat64', 'lstat64'].forEach(mswHookNativePath);
  ['open', 'open64'].forEach(function (api) { mswHookNativeOpen(api, false); });
  mswHookNativeOpen('fopen', true);

  if (!Java.available) {
    send({ event: 'script_loaded', script: 'bypass-root-detection', java: false });
    return;
  }

  Java.perform(function () {
    const File = Java.use('java.io.File');
    const fileExists = File.exists.overload();
    fileExists.implementation = function () {
      const path = String(this.getAbsolutePath());
      if (mswLooksLikeRootPath(path)) {
        mswReport('java.io.File.exists', path);
        return false;
      }
      return fileExists.call(this);
    };

    const fileCanExecute = File.canExecute.overload();
    fileCanExecute.implementation = function () {
      const path = String(this.getAbsolutePath());
      if (mswLooksLikeRootPath(path)) {
        mswReport('java.io.File.canExecute', path);
        return false;
      }
      return fileCanExecute.call(this);
    };

    const IOException = Java.use('java.io.IOException');
    const Runtime = Java.use('java.lang.Runtime');
    [
      ['java.lang.String'],
      ['[Ljava.lang.String;'],
      ['java.lang.String', '[Ljava.lang.String;'],
      ['[Ljava.lang.String;', '[Ljava.lang.String;'],
      ['java.lang.String', '[Ljava.lang.String;', 'java.io.File'],
      ['[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File']
    ].forEach(function (signature) {
      let overload;
      try {
        overload = Runtime.exec.overload.apply(Runtime.exec, signature);
      } catch (_) {
        return;
      }
      overload.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        const command = mswCommandText(args[0]);
        if (mswLooksLikeRootProbe(command)) {
          mswReport('java.lang.Runtime.exec', command);
          throw IOException.$new('Permission denied');
        }
        return overload.apply(this, args);
      };
    });

    try {
      const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
      const start = ProcessBuilder.start.overload();
      start.implementation = function () {
        const command = this.command().toString();
        if (mswLooksLikeRootProbe(command)) {
          mswReport('java.lang.ProcessBuilder.start', command);
          throw IOException.$new('Permission denied');
        }
        return start.call(this);
      };
    } catch (_) {
      // ProcessBuilder layout can differ on vendor runtimes.
    }

    try {
      const SystemProperties = Java.use('android.os.SystemProperties');
      const masked = {
        'ro.build.tags': 'release-keys',
        'ro.debuggable': '0',
        'ro.secure': '1',
        'service.adb.root': '0'
      };
      const getOne = SystemProperties.get.overload('java.lang.String');
      getOne.implementation = function (key) {
        const name = String(key);
        if (Object.prototype.hasOwnProperty.call(masked, name)) {
          mswReport('android.os.SystemProperties.get', name);
          return masked[name];
        }
        return getOne.call(this, key);
      };
      const getDefault = SystemProperties.get.overload(
        'java.lang.String',
        'java.lang.String'
      );
      getDefault.implementation = function (key, fallback) {
        const name = String(key);
        if (Object.prototype.hasOwnProperty.call(masked, name)) {
          mswReport('android.os.SystemProperties.get', name);
          return masked[name];
        }
        return getDefault.call(this, key, fallback);
      };
    } catch (_) {
      // Hidden API access varies by Android release.
    }

    try {
      const Build = Java.use('android.os.Build');
      Build.TAGS.value = 'release-keys';
      Build.TYPE.value = 'user';
    } catch (_) {
      // Read-only fields on some runtimes cannot be replaced.
    }

    try {
      const PackageManager = Java.use('android.app.ApplicationPackageManager');
      const NameNotFound = Java.use(
        'android.content.pm.PackageManager$NameNotFoundException'
      );
      const packageInfo = PackageManager.getPackageInfo.overload(
        'java.lang.String',
        'int'
      );
      packageInfo.implementation = function (packageName, flags) {
        if (mswLooksLikeRootPackage(packageName)) {
          mswReport('PackageManager.getPackageInfo', packageName);
          throw NameNotFound.$new(String(packageName));
        }
        return packageInfo.call(this, packageName, flags);
      };
      const applicationInfo = PackageManager.getApplicationInfo.overload(
        'java.lang.String',
        'int'
      );
      applicationInfo.implementation = function (packageName, flags) {
        if (mswLooksLikeRootPackage(packageName)) {
          mswReport('PackageManager.getApplicationInfo', packageName);
          throw NameNotFound.$new(String(packageName));
        }
        return applicationInfo.call(this, packageName, flags);
      };
    } catch (_) {
      // PackageManager implementation differs across vendor Android builds.
    }

    mswHookBooleanMethods('com.scottyab.rootbeer.RootBeer', [
      'isRooted',
      'isRootedWithoutBusyBoxCheck',
      'detectRootManagementApps',
      'detectPotentiallyDangerousApps',
      'checkForBinary',
      'checkForDangerousProps',
      'checkForRWPaths',
      'detectTestKeys',
      'checkSuExists',
      'checkForRootNative'
    ]);

    send({
      event: 'script_loaded',
      script: 'bypass-root-detection',
      risk: 'high',
      automatic: false
    });
  });
});
