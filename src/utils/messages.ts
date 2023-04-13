import { IRoboDroidMessage } from '@robodroid/utils/interfaces';

export const sendFailed = (msg: string) => {
  const message: IRoboDroidMessage = {
    msg: msg,
    status: 'failed'
  }
  send(JSON.stringify(message));
}

export const sendCompleted = (msg: string, outputs?: any) => {
  let message: IRoboDroidMessage = {
    msg: msg,
    status: 'completed'
  }
  if (outputs) {
    message['outputs'] = outputs;
  }
  send(JSON.stringify(message));
}