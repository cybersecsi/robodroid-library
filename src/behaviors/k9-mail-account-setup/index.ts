import { wrapJavaPerform, waitForInstanceLoaded, startActivity } from '@robodroid/utils/libjava';
import { sendCompleted } from '@robodroid/utils/messages';
import { LogLevel } from '@robodroid/utils/types';
import { logger } from '@robodroid/utils/logger';

// Input interface
interface IEmailInput {
  email: string;
  password: string;
  incomingServer: string;
  incomingPort: number;
  outgoingServer: string;
  outgoingPort: number;
}

// Generic classes
const stringClass = Java.use("java.lang.String");

const performAccountSetupBasics = (emailInput: IEmailInput): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupBasics", {
      onMatch: (instance) => {
        const email = stringClass.$new(emailInput.email);
        Java.scheduleOnMainThread(() => {
          instance.emailView.value.setText(email, null);
          instance.onManualSetup();
        });
      },
      onComplete: () => {},
    });
  })
};

const performAccountSetupType = () => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupAccountType", {
      onMatch: (instance) => {
        instance.setupImapAccount();
      },
      onComplete: () => {},
    });
  })
};

const performAccountSetupIncoming = (emailInput: IEmailInput): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupIncoming", {
      onMatch: (instance) => {
        const email = stringClass.$new(emailInput.email);
        const serverHost = stringClass.$new(emailInput.incomingServer);
        const serverPort = stringClass.$new(emailInput.incomingPort.toString());
        const password = stringClass.$new(emailInput.password);
        Java.scheduleOnMainThread(() => {
          instance.mPasswordView.value.setText(password, null);
          instance.mUsernameView.value.setText(email, null);
          instance.mServerView.value.setText(serverHost, null);
          instance.mPortView.value.setText(serverPort, null);
          instance.onNext();
        });
      },
      onComplete: () => {},
    });
  });
};

const performAccountSetupOutgoing = (emailInput: IEmailInput): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupOutgoing", {
      onMatch: (instance) => {
        const email = stringClass.$new(emailInput.email);
        const serverHost = stringClass.$new(emailInput.outgoingServer);
        const serverPort = stringClass.$new(emailInput.outgoingPort.toString());
        const password = stringClass.$new(emailInput.password);
        instance.mUsernameView.value.setText(email, null);
        instance.mServerView.value.setText(serverHost, null);
        instance.mPortView.value.setText(serverPort, null);
        instance.mPasswordView.value.setText(password, null);
        instance.mPasswordView.value.setText(password, null);
        instance.mSecurityTypeView.value.setSelection(1, false);
        instance.onNext();
      },
      onComplete: () => {},
    });
  })
};

const performAccountSetupOptions = (): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupOptions", {
      onMatch: (instance) => {
        instance.onDone();
      },
      onComplete: () => {},
    });
  })
};

const performAccountSetupNames = (emailInput: IEmailInput): Promise<void> => {
  return wrapJavaPerform(() => {
    Java.choose("com.fsck.k9.activity.setup.AccountSetupNames", {
      onMatch: (instance) => {
        const email = stringClass.$new(emailInput.email);
        Java.scheduleOnMainThread(() => {
          instance.mName.value.setText(email, null);
          instance.onNext();
        });
      },
      onComplete: () => {},
    });
  })
};

export const startBehavior = (
  email: string, 
  password: string, 
  incomingServer: string, 
  incomingPort: number, 
  outgoingServer: string, 
  outgoingPort: number,
  logLevel?: LogLevel
  ) => {
    setTimeout(async function () {
      logger.setLogLevel(logLevel ?? "normal")
      const emailInput: IEmailInput = {
        email, password, incomingServer, incomingPort, outgoingServer, outgoingPort
      }
      //await waitForInstanceLoaded("com.fsck.k9.ui.onboarding.OnboardingActivity");
      await startActivity("com.fsck.k9.activity.setup.AccountSetupBasics");
      await waitForInstanceLoaded(
        "com.fsck.k9.activity.setup.AccountSetupBasics",
        logger
      );
      await performAccountSetupBasics(emailInput);
      await waitForInstanceLoaded(
        "com.fsck.k9.activity.setup.AccountSetupAccountType",
        logger
      );
      await performAccountSetupType();
      await waitForInstanceLoaded(
        "com.fsck.k9.activity.setup.AccountSetupIncoming",
        logger
      );
      await performAccountSetupIncoming(emailInput);
      await waitForInstanceLoaded(
        "com.fsck.k9.activity.setup.AccountSetupOutgoing",
        logger,
        3000
      );
      await performAccountSetupOutgoing(emailInput);
      await waitForInstanceLoaded(
        "com.fsck.k9.activity.setup.AccountSetupOptions",
        logger,
        1000
      );
      await performAccountSetupOptions();
      await waitForInstanceLoaded("com.fsck.k9.activity.setup.AccountSetupNames", logger);
      await performAccountSetupNames(emailInput);
      await waitForInstanceLoaded("com.fsck.k9.activity.MessageList", logger);
      sendCompleted("Account setup completed");
    }, 0);
}
