'use strict';

const MSW_TEST_VALUES = Object.freeze({
  '성명': 'MSW_TEST_A5F47C17',
  '주민번호 앞자리': '000000',
  '주민번호 뒷자리': '0000000'
});

const MSW_FIELD_LABELS = Object.keys(MSW_TEST_VALUES);

function mswSend(event, details) {
  send(Object.assign({
    event: event,
    control: 'authorized_synthetic_registration',
    run_marker: 'a5f47c17'
  }, details || {}));
}

function mswSafeString(value) {
  try {
    if (mswIsNull(value)) return '';
    return String(value);
  } catch (_) {
    return '';
  }
}

function mswIsNull(value) {
  if (value === null || value === undefined) return true;
  try {
    if (value.handle && value.handle.isNull) return value.handle.isNull();
    if (value.isNull && typeof value.isNull === 'function') return value.isNull();
  } catch (_) {}
  return false;
}

function mswArrayItems(array) {
  const items = [];
  if (mswIsNull(array)) return items;
  const count = Number(array.count());
  for (let index = 0; index < count; index += 1) {
    items.push(array.objectAtIndex_(index));
  }
  return items;
}

function mswCallString(object, selector) {
  try {
    if (!object.respondsToSelector_(selector)) return '';
    return mswSafeString(object[selector]());
  } catch (_) {
    return '';
  }
}

function mswDescribe(object) {
  return {
    class_name: mswSafeString(object.$className),
    accessibility_label: mswCallString(object, 'accessibilityLabel'),
    accessibility_value: mswCallString(object, 'accessibilityValue'),
    accessibility_frame: mswCallString(object, 'accessibilityFrame')
  };
}

function mswVisible(object) {
  try {
    if (object.respondsToSelector_('isAccessibilityElement') && object.isAccessibilityElement()) {
      const frame = object.accessibilityFrame();
      return Number(frame.size.width) > 0 && Number(frame.size.height) > 0;
    }
    return !object.hidden() && Number(object.alpha()) > 0.01 && !mswIsNull(object.window());
  } catch (_) {
    return false;
  }
}

function mswCollect(object, output, seen) {
  if (mswIsNull(object)) return;
  const key = String(object.handle);
  if (seen[key]) return;
  seen[key] = true;
  output.push(object);

  try {
    mswArrayItems(object.subviews()).forEach(function (child) {
      mswCollect(child, output, seen);
    });
  } catch (_) {}

  try {
    if (object.respondsToSelector_('accessibilityElements')) {
      mswArrayItems(object.accessibilityElements()).forEach(function (element) {
        mswCollect(element, output, seen);
      });
    }
  } catch (_) {}

  try {
    if (object.respondsToSelector_('accessibilityElementCount')) {
      const count = Number(object.accessibilityElementCount());
      for (let index = 0; index < count && index < 200; index += 1) {
        mswCollect(object.accessibilityElementAtIndex_(index), output, seen);
      }
    }
  } catch (_) {}
}

function mswAllObjects() {
  const output = [];
  const seen = {};
  const app = ObjC.classes.UIApplication.sharedApplication();
  mswArrayItems(app.windows()).forEach(function (window) {
    mswCollect(window, output, seen);
  });
  return output;
}

function mswFindFirstResponder() {
  const objects = mswAllObjects();
  for (let index = 0; index < objects.length; index += 1) {
    const object = objects[index];
    try {
      if (object.respondsToSelector_('isFirstResponder') && object.isFirstResponder()) {
        return object;
      }
    } catch (_) {}
  }
  return null;
}

function mswActivate(object) {
  try {
    if (!object.respondsToSelector_('accessibilityActivate')) return false;
    return Boolean(object.accessibilityActivate());
  } catch (_) {
    return false;
  }
}

function mswInsertValue(label, target, value, completion) {
  if (!mswActivate(target)) {
    completion('accessibility_activate_failed');
    return;
  }

  setTimeout(function () {
    try {
      const responder = mswFindFirstResponder();
      if (!responder) {
        completion('first_responder_not_found');
        return;
      }

      const existing = mswCallString(target, 'accessibilityValue').trim();
      if (existing !== '') {
        completion('field_not_empty');
        return;
      }

      if (responder.respondsToSelector_('setText:')) {
        responder.setText_(value);
      } else if (responder.respondsToSelector_('insertText:')) {
        responder.insertText_(value);
      } else {
        completion('first_responder_not_text_input');
        return;
      }

      try {
        if (responder.respondsToSelector_('sendActionsForControlEvents:')) {
          responder.sendActionsForControlEvents_(131072);
        }
      } catch (_) {}

      mswSend('registration_field_filled', {
        field: label,
        value: value,
        responder_class: mswSafeString(responder.$className)
      });
      completion(null);
    } catch (error) {
      completion('input_exception:' + String(error));
    }
  }, 350);
}

function mswFillSequentially(targets, index, completion) {
  if (index >= MSW_FIELD_LABELS.length) {
    completion(null);
    return;
  }
  const label = MSW_FIELD_LABELS[index];
  mswInsertValue(label, targets[label], MSW_TEST_VALUES[label], function (error) {
    if (error) {
      completion(label + ':' + error);
      return;
    }
    mswFillSequentially(targets, index + 1, completion);
  });
}

function mswMain() {
  if (!ObjC.available) {
    mswSend('registration_failed', { reason: 'objc_runtime_unavailable' });
    return;
  }

  ObjC.schedule(ObjC.mainQueue, function () {
    try {
      const objects = mswAllObjects().filter(mswVisible);
      const labeled = objects.filter(function (object) {
        return mswCallString(object, 'accessibilityLabel').trim() !== '';
      });
      const targets = {};
      const counts = {};

      MSW_FIELD_LABELS.forEach(function (label) {
        const matches = labeled.filter(function (object) {
          return mswCallString(object, 'accessibilityLabel').trim() === label;
        });
        counts[label] = matches.length;
        if (matches.length === 1) targets[label] = matches[0];
      });

      const registerControls = labeled.filter(function (object) {
        return mswCallString(object, 'accessibilityLabel').trim() === '등록';
      });

      const invalidField = MSW_FIELD_LABELS.some(function (label) {
        return counts[label] !== 1;
      });
      if (invalidField || registerControls.length !== 1) {
        mswSend('registration_failed', {
          reason: 'unexpected_accessibility_controls',
          field_counts: counts,
          register_count: registerControls.length,
          observed_labeled_controls: labeled.slice(0, 40).map(mswDescribe)
        });
        return;
      }

      const nonEmpty = MSW_FIELD_LABELS.filter(function (label) {
        return mswCallString(targets[label], 'accessibilityValue').trim() !== '';
      });
      if (nonEmpty.length > 0) {
        mswSend('registration_failed', { reason: 'target_fields_not_empty', fields: nonEmpty });
        return;
      }

      mswFillSequentially(targets, 0, function (error) {
        if (error) {
          mswSend('registration_failed', { reason: error });
          return;
        }
        setTimeout(function () {
          const activated = mswActivate(registerControls[0]);
          mswSend(activated ? 'registration_submitted' : 'registration_failed', {
            reason: activated ? 'exact_swiftui_control_activated' : 'register_control_activation_failed',
            test_values: MSW_TEST_VALUES,
            target_control: mswDescribe(registerControls[0])
          });
        }, 400);
      });
    } catch (error) {
      mswSend('registration_failed', { reason: 'exception', error: String(error) });
    }
  });
}

setTimeout(mswMain, 250);
