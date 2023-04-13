import {
  wrapJavaPerform,
  getResource,
  waitForInstanceLoaded,
  waitForResourceVisible,
  getCurrentActivity
} from "@robodroid/utils/libjava";
import {
  ACTION_VIEW,
  intentClassName,
  stringClassName,
  uriClassName,
  startActivityMethod,
} from "@robodroid/utils/constants";
import { LogLevel } from '@robodroid/utils/types';
import { logger } from '@robodroid/utils/logger';
import { sendCompleted, sendFailed } from '@robodroid/utils/messages';

// Generic classes
const intentClass = Java.use(intentClassName);
const uriClass = Java.use(uriClassName);
const stringClass = Java.use(stringClassName);

const openLink = (link: string): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose('org.mozilla.fenix.HomeActivity', {
      onMatch: (instance: Java.Wrapper<any>) => {
        // Create intent
        const parsedLink = uriClass.parse(stringClass.$new(link));
        const actionView = stringClass.$new(ACTION_VIEW);
        const intent = intentClass.$new(actionView, parsedLink);
        intent.setPackage('org.mozilla.firefox')

        // Open link
        instance[startActivityMethod](intent)

      },
      onComplete: () => {}
    })
  })
}

const clickDownload = (): Promise<void> => {
  return wrapJavaPerform(async () => {
    const appCompatButtonClass = Java.use(
      "androidx.appcompat.widget.AppCompatButton"
    );
    const resourceId = await getResource("download_button", "id");
    const currentActivity = await getCurrentActivity();
    const btnToClick = currentActivity?.findViewById(resourceId);
    const downloadBtn = Java.cast(btnToClick, appCompatButtonClass);
    Java.scheduleOnMainThread(() => {
      downloadBtn.performClick();
    });
  });
};

// DEPRECATED: File is not opened
const openDownload = (): Promise<void> => {
  return wrapJavaPerform(async () => {
    const materialButtonClass = Java.use(
      "com.google.android.material.button.MaterialButton"
    );
    const resourceId = await getResource("download_dialog_action_button", "id");
    const currentActivity = await getCurrentActivity();
    const btnToClick = currentActivity?.findViewById(resourceId);
    const openBtn = Java.cast(btnToClick, materialButtonClass);
    Java.scheduleOnMainThread(() => {
      openBtn.performClick();
    });
  });
};

const hookDownloadStart = (): Promise<void> => {
  return wrapJavaPerform(() => {
    const cls = Java.use("mozilla.components.support.utils.DownloadUtils");
    cls.uniqueFileName.implementation = function () {
      const retval = this.uniqueFileName.apply(this, arguments);
      const dstDir = arguments[0];
      const fileName = retval;
      const filePath = `${dstDir}/${fileName}`;
      hookDownloadComplete(filePath)
      return retval;
    };
  });
};

const hookDownloadComplete = (filePath: string) => {
  return wrapJavaPerform(() => {
    const cls = Java.use("mozilla.components.feature.downloads.manager.FetchDownloadManager");
    cls.onReceive.implementation = function () {
      const retval = this.onReceive.apply(this, arguments);
      sendCompleted("File download completed!", {filePath: filePath});
      return retval;
    };
  });
}


export const startBehavior = (link: string, logLevel?: LogLevel) => {
  setTimeout(async function () {
    logger.setLogLevel(logLevel ?? "normal")
    await openLink(link);
    await hookDownloadStart();
    await waitForInstanceLoaded("android.app.ActivityThread", logger);
    await waitForInstanceLoaded(
      "mozilla.components.feature.downloads.DownloadsFeature",
      logger
    );
    await waitForResourceVisible("download_button", "id", logger);
    await clickDownload()
  })
}