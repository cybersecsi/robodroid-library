<h1 align="center">
  <br>
    <img src="https://raw.githubusercontent.com/cybersecsi/robodroid-library/main/logo.png" alt= "robodroid" width="300px">
</h1>
<p align="center">
    <b>RoboDroid Library</b>
<p>
RoboDroid Library is a curated list of Frida scripts for RoboDroid to run pre-defined behaviors. It is tailored for CyberRange usage to simulate the behavior of a human-like smartphone user. The library contains pre-defined behaviors that can be run on a target device to test its security posture.

<!-- omit in toc -->
## Table of Contents
- [Context](#context)
- [Overview](#overview)
- [Behaviors](#behaviors)
- [Credits](#credits)
- [License](#license)


## Context
Mobile devices have become ubiquitous in today's world. People use smartphones for almost every aspect of their lives, including banking, shopping, and communication. As a result, mobile devices are now a primary target for cybercriminals.

However, the security of mobile devices is often overlooked in cybersecurity training and testing environments. This can leave organizations vulnerable to attacks that exploit the weaknesses of mobile devices. Therefore, it is important to introduce mobile components in next-generation cyber-ranges to adapt to the current world that is more and more smartphone-addicted.

**RoboDroid Library** is designed to help fill this gap by providing a set of tools that can simulate human-like smartphone behavior. 
These scripts are meant to be run with the actual CLI tool [RoboDroid](https://github.com/cybersecsi/robodroid)

## Overview
RoboDroid Library is a curated list of Frida scripts that can be used to simulate the behavior of a human-like smartphone user. The library is designed to be used in CyberRange environments, where it can be used to test the security posture of mobile devices and applications.

The scripts in RoboDroid Library are written using the Frida framework. Frida is a dynamic instrumentation toolkit that can be used to inject code into running processes. This allows the scripts in RoboDroid Library to interact with the target device in real-time, as if they were being run by a human user.

We hope that RoboDroid Library will be a valuable resource for students, cybersecurity professionals and researchers.

## Behaviors
Currently all the available behaviors are created using **open-source applications** since it could be painful to use closed-source applications.

| **Behavior** | **Description** |
|---|---|
| firefox-android-open-and-download | This behavior automatically performs the download of a given resource based on an input URL using the Firefox Android app. |
| k9-mail-refresh-and-get-link | This behavior automatically waits for new emails in the K9 Mail app, opens the last one and returns the first link found in the email. This is a common attack vector, as cybercriminals often use phishing emails to trick users into clicking on malicious links. |
| k9-mail-account-setup | This behavior automatically performs the setup of an email account on the K9 Mail Android app. |

Users are encouraged to create their own scripts using the Frida framework and add them to the library through a Pull Request.

## Credits

Developed by Angelo Delicato [@SecSI](https://secsi.io)

## License

_robodroid-library_ is released under the [GPL-3.0 LICENSE](https://github.com/cybersecsi/robodroid-library/blob/main/LICENSE)
