// all Java calls need to be wrapped in a Java.perform().
// this helper just wraps that into a Promise that the
// rpc export will sniff and resolve before returning

import { IRoboDroidLogger } from "@robodroid/utils/interfaces";
import { Activity, ActivityClientRecord, ActivityThread, PackageManager, Intent } from "@robodroid/utils/types";
import { FLAG_ACTIVITY_NEW_TASK } from "@robodroid/utils/constants";

// the result when its ready.
export const wrapJavaPerform = (fn: any): Promise<any> => {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        resolve(fn());
      } catch (e) {
        reject(e);
      }
    });
  });
};

export const getApplicationContext = (): any => {
  const ActivityThread = Java.use("android.app.ActivityThread");
  const currentApplication = ActivityThread.currentApplication();

  return currentApplication.getApplicationContext();
};

export const getResource = (name: string, type: string): any => {
  const context = getApplicationContext();
  return context.getResources().getIdentifier(name, type, context.getPackageName());
}

export const getCurrentActivity = (): Java.Wrapper | null => {
  const activityThread: ActivityThread = Java.use("android.app.ActivityThread");
  const activity: Activity = Java.use("android.app.Activity");
  const activityClientRecord: ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");

  const currentActivityThread = activityThread.currentActivityThread();
  const activityRecords = currentActivityThread.mActivities.value.values().toArray();
  let currentActivity;

  for (const i of activityRecords) {
    const activityRecord = Java.cast(i, activityClientRecord);
    if (!activityRecord.paused.value) {
      currentActivity = Java.cast(Java.cast(activityRecord, activityClientRecord).activity.value, activity);
      break;
    }
  }

  if (currentActivity) {
    return currentActivity;
  }

  return null;
};

export const getActivities = (): string[] => {
  const packageManager: PackageManager = Java.use("android.content.pm.PackageManager");
  const GET_ACTIVITIES = packageManager.GET_ACTIVITIES.value;
  const context = getApplicationContext();

  return Array.prototype.concat(context.getPackageManager()
    .getPackageInfo(context.getPackageName(), GET_ACTIVITIES).activities.value.map((activityInfo: Activity) => {
      return activityInfo.name.value;
    }),
  );
};

export const startActivity = (activityClass: string): Promise<void> => {
  return wrapJavaPerform(() => {
    // -- Sample Java
    //
    // Intent intent = new Intent(this, DisplayMessageActivity.class);
    // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    //
    // startActivity(intent);
    const context = getApplicationContext();

    // Setup a new Intent
    const androidIntent: Intent = Java.use("android.content.Intent");

    // Get the Activity class's .class
    const newActivity: Java.Wrapper = Java.use(activityClass).class;

    // Init and launch the intent
    const newIntent: Intent = androidIntent.$new(context, newActivity);
    newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

    context.startActivity(newIntent);
  })
};

// starts an Android service
export const startService = (serviceClass: string): Promise<void> => {
  return wrapJavaPerform(() => {
    // -- Sample Java
    //
    // Intent intent = new Intent(this, Service.class);
    // intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    //
    // startService(intent);
    const context = getApplicationContext();

    // Setup a new Intent
    const androidIntent: Intent = Java.use("android.content.Intent");

    // Get the Activity class's .class
    const newService: string = Java.use(serviceClass).$className;

    // Init and launch the intent
    const newIntent: Intent = androidIntent.$new(context, newService);
    newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);

    context.startService(newIntent);
  })
};

export const getFirstInstance = (className: string): any | null => {
  let instances: any = [];
  Java.choose(className, {
    onMatch: (instance) => {
      instances.push(instance);
    },
    onComplete: () => {},
  });
  return instances.length > 0 ? instances[0] : null;
}

export const waitForInstanceLoaded = (className: string, logger: IRoboDroidLogger, timeout: number = 500): Promise<void> => {
  return new Promise((resolve) => {
    Java.perform(() => {
      function checkInstances() {
        let instances = [];
        Java.choose(className, {
          onMatch: (instance) => {
            instances.push(instance);
            resolve();
          },
          onComplete: () => {
            if (instances.length == 0) {
              const errMsg = `Unable to retrieve live instance(s) of '${className}', retrying in ${timeout}ms...`;
              logger.debug(errMsg);
              setTimeout(checkInstances, timeout);
            } else {
              logger.log(`Instance of '${className}' correctly loaded`);
            }
          },
        });
      }
      checkInstances();
    })
  });
}

export const  waitForResourceVisible = (resourceName: string, resourceType: string, logger: IRoboDroidLogger, timeout: number = 500): Promise<void> => {
  return new Promise((resolve) => {
    Java.perform(() => {
      async function checkResource() {
        const resourceId = await getResource(resourceName, resourceType);
        const currentActivity = getCurrentActivity();
        const view = currentActivity?.findViewById(resourceId);
        if (view !== null && view !== undefined) {
          resolve();
        } else {
          logger.debug(
            `Resource '${resourceName}' is not visible yet, retrying in ${timeout}ms...`
          );
          setTimeout(checkResource, timeout);
        }
      }
      checkResource();
    })
  });
}