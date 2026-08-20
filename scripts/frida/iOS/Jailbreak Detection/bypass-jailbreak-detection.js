'use strict';

const MSW_JAILBREAK_PATHS = [
  '/Applications/Cydia.app',
  '/Applications/Sileo.app',
  '/Applications/Zebra.app',
  '/Library/MobileSubstrate/MobileSubstrate.dylib',
  '/Library/PreferenceLoader',
  '/bin/bash',
  '/bin/sh',
  '/etc/apt',
  '/private/var/lib/apt',
  '/private/var/lib/cydia',
  '/private/var/stash',
  '/usr/bin/ssh',
  '/usr/libexec/sftp-server',
  '/var/cache/apt',
  '/var/jb'
];

let mswEventCount = 0;

function mswReport(api, value) {
  if (mswEventCount >= 200) return;
  mswEventCount += 1;
  send({
    event: 'security_control_bypass',
    control: 'jailbreak_detection',
    api: api,
    value: String(value),
    action: 'masked',
    sequence: mswEventCount
  });
}

function mswLooksLikeJailbreakPath(value) {
  if (!value) return false;
  const path = String(value).toLowerCase();
  return MSW_JAILBREAK_PATHS.some(function (item) {
    const lowered = item.toLowerCase();
    return path === lowered || path.indexOf(lowered + '/') === 0;
  }) || /(^|\/)(cydia|sileo|zebra|mobilesubstrate|substrate|substitute)(\/|$)/i.test(path);
}

function mswReadCString(pointer) {
  try {
    return pointer.isNull() ? '' : pointer.readUtf8String();
  } catch (_) {
    return '';
  }
}

function mswHookPathFunction(api) {
  const address = Module.findExportByName(null, api);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.mswPath = mswReadCString(args[0]);
      this.mswMask = mswLooksLikeJailbreakPath(this.mswPath);
    },
    onLeave(retval) {
      if (!this.mswMask) return;
      mswReport('libc.' + api, this.mswPath);
      retval.replace(-1);
    }
  });
}

function mswHookOpenFunction(api, pointerResult) {
  const address = Module.findExportByName(null, api);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.mswPath = mswReadCString(args[0]);
      this.mswMask = mswLooksLikeJailbreakPath(this.mswPath);
    },
    onLeave(retval) {
      if (!this.mswMask) return;
      mswReport('libc.' + api, this.mswPath);
      retval.replace(pointerResult ? ptr(0) : -1);
    }
  });
}

setImmediate(function () {
  ['access', 'stat', 'lstat', 'stat64', 'lstat64'].forEach(mswHookPathFunction);
  ['open', 'open_nocancel'].forEach(function (api) {
    mswHookOpenFunction(api, false);
  });
  mswHookOpenFunction('fopen', true);

  const getenvAddress = Module.findExportByName(null, 'getenv');
  if (getenvAddress) {
    Interceptor.attach(getenvAddress, {
      onEnter(args) {
        this.mswName = mswReadCString(args[0]);
      },
      onLeave(retval) {
        if (this.mswName !== 'DYLD_INSERT_LIBRARIES') return;
        mswReport('libc.getenv', this.mswName);
        retval.replace(ptr(0));
      }
    });
  }

  const forkAddress = Module.findExportByName(null, 'fork');
  if (forkAddress) {
    Interceptor.replace(forkAddress, new NativeCallback(function () {
      mswReport('libc.fork', 'blocked');
      return -1;
    }, 'int', []));
  }

  if (ObjC.available) {
    const NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager && NSFileManager['- fileExistsAtPath:']) {
      Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter(args) {
          this.mswPath = new ObjC.Object(args[2]).toString();
          this.mswMask = mswLooksLikeJailbreakPath(this.mswPath);
        },
        onLeave(retval) {
          if (!this.mswMask) return;
          mswReport('NSFileManager.fileExistsAtPath', this.mswPath);
          retval.replace(0);
        }
      });
    }
    if (NSFileManager && NSFileManager['- fileExistsAtPath:isDirectory:']) {
      Interceptor.attach(
        NSFileManager['- fileExistsAtPath:isDirectory:'].implementation,
        {
          onEnter(args) {
            this.mswPath = new ObjC.Object(args[2]).toString();
            this.mswMask = mswLooksLikeJailbreakPath(this.mswPath);
          },
          onLeave(retval) {
            if (!this.mswMask) return;
            mswReport('NSFileManager.fileExistsAtPath:isDirectory', this.mswPath);
            retval.replace(0);
          }
        }
      );
    }
    if (NSFileManager && NSFileManager['- isWritableFileAtPath:']) {
      Interceptor.attach(
        NSFileManager['- isWritableFileAtPath:'].implementation,
        {
          onEnter(args) {
            this.mswPath = new ObjC.Object(args[2]).toString();
            this.mswMask = mswLooksLikeJailbreakPath(this.mswPath);
          },
          onLeave(retval) {
            if (!this.mswMask) return;
            mswReport('NSFileManager.isWritableFileAtPath', this.mswPath);
            retval.replace(0);
          }
        }
      );
    }

    const UIApplication = ObjC.classes.UIApplication;
    if (UIApplication && UIApplication['- canOpenURL:']) {
      Interceptor.attach(UIApplication['- canOpenURL:'].implementation, {
        onEnter(args) {
          this.mswUrl = new ObjC.Object(args[2]).absoluteString().toString();
          this.mswMask = /^(cydia|sileo|zbra|filza|activator):/i.test(this.mswUrl);
        },
        onLeave(retval) {
          if (!this.mswMask) return;
          mswReport('UIApplication.canOpenURL', this.mswUrl);
          retval.replace(0);
        }
      });
    }
  }

  send({
    event: 'script_loaded',
    script: 'bypass-jailbreak-detection',
    risk: 'high',
    automatic: false
  });
});
