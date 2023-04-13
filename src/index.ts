import { LogLevel } from "@robodroid/utils/types";
import { startBehavior as K9MailRefreshAndGetLink } from "@robodroid/behaviors/k9-mail-refresh-and-get-link";
import { startBehavior as K9MailAccountSetup } from "@robodroid/behaviors/k9-mail-account-setup";
import { startBehavior as firefoxAndroidOpenAndDownload } from "@robodroid/behaviors/firefox-android-open-and-download";

rpc.exports = {
  k9MailRefreshAndGetLink: (logLevel?: LogLevel) => K9MailRefreshAndGetLink(logLevel),
  k9MailAccountSetup: (  
    email: string, 
    password: string, 
    incomingServer: string, 
    incomingPort: number, 
    outgoingServer: string, 
    outgoingPort: number,
    logLevel?: LogLevel
    ) => K9MailAccountSetup(email, password, incomingServer, incomingPort, outgoingServer, outgoingPort, logLevel),
  firefoxAndroidOpenAndDownload: (link: string, logLevel?: LogLevel) => firefoxAndroidOpenAndDownload(link, logLevel),
}