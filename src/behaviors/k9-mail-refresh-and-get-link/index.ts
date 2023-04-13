import { wrapJavaPerform, waitForInstanceLoaded, getFirstInstance } from '@robodroid/utils/libjava';
import { sendCompleted, sendFailed } from '@robodroid/utils/messages';
import { LogLevel } from '@robodroid/utils/types';
import { logger } from '@robodroid/utils/logger';


// App-specific class names
const messageListClassName = "com.fsck.k9.activity.MessageList";
const messageListActivityListener =
  "com.fsck.k9.ui.messagelist.MessageListFragment$MessageListActivityListener";
const messageListFragmentClassName =
  "com.fsck.k9.ui.messagelist.MessageListFragment";
const messageReferenceClassName = "com.fsck.k9.controller.MessageReference";
const messageContainerViewClassName =
  "com.fsck.k9.ui.messageview.MessageContainerView";
const preferencesClassName = "com.fsck.k9.Preferences";

//Constants
const linkRegex = /<a\s+[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>/i;

// Global variables
let mailAccount: any;
let inboxFolderId: any;
let newMessage: any;

const setPreferences = (): Promise<void> => {
  return wrapJavaPerform(() => {
    let instances = [];
    Java.choose(preferencesClassName, {
      onMatch: (instance) => {
        instances.push(instance);
        const accounts = instance.getAccounts();
        mailAccount = accounts.get(0);
        inboxFolderId = instance.getAccount(mailAccount.toString()).inboxFolderId
          .value;
      },
      onComplete: () => {},
    });
  })
};

const doRefresh = (): Promise<void> => {
  return wrapJavaPerform(() => {
    logger.debug("Performing refresh");
    Java.choose(messageListFragmentClassName, {
      onMatch: (instance) => {
        instance.checkMail();
        return "stop";
      },
      onComplete: () => {},
    });
  })
};

const addSaveNewUidMessageHook = (): Promise<void> => {
  return wrapJavaPerform(() => {
    logger.log(
      "Adding a new hook to automatically open new emails upon arrival"
    );
    const activityListenerCls = Java.use(messageListActivityListener);

    activityListenerCls.synchronizeMailboxNewMessage.implementation =
      function () {
        const retval = this.synchronizeMailboxNewMessage.apply(this, arguments);

        // Get local message and mUid
        const localMessage = arguments[2];
        const mUid = localMessage.mUid.value;
        if (newMessage === undefined) {
          newMessage = mUid;
          openNewMessage(newMessage);
        }
        return retval;
      };
  })
};

const openNewMessage = (mUid: number): Promise<void> => {
  return wrapJavaPerform(async () => {
    // Get message reference
    const messageReferenceCls = Java.use(messageReferenceClassName);

    const messageReferenceInstance = messageReferenceCls.$new(
      mailAccount.toString(),
      inboxFolderId.longValue(),
      mUid
    );
    // Retrieve instance of MessageList
    const instance = getFirstInstance(messageListClassName)
    // Open new email
    if (instance !== null) {
      logger.log("Opening message...");
      Java.scheduleOnMainThread(function () {
        instance.openMessage(messageReferenceInstance);
      });
      await waitForInstanceLoaded(messageContainerViewClassName, logger, 1000);
      // Reset newMessage value
      newMessage = undefined;
      openLinkInMail();
    }
  })
};

const openLinkInMail = (): Promise<void> => {
  return wrapJavaPerform(() => {
    const instance = getFirstInstance(messageContainerViewClassName)
    // Open link
    if (instance !== null) {
      const HtmlText = instance.currentHtmlText.value;
      const match = HtmlText.match(linkRegex);
      if (match) {
        var linkUrl = match[1];
        sendCompleted("Link found!", {link: linkUrl});
      } else {
        sendFailed("Link not found");
      }
    }
  })
};

export const startBehavior = (logLevel?: LogLevel) => {
  setTimeout(async function () {
    logger.setLogLevel(logLevel ?? "normal")
    await waitForInstanceLoaded(preferencesClassName, logger);
    await setPreferences();
    await addSaveNewUidMessageHook();
    setInterval(async () => {
      await doRefresh();
    }, 5000);
  }, 0);
}