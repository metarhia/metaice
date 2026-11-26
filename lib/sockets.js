'use strict';

const CLOSED_CODES = ['ERR_SOCKET_DGRAM_NOT_RUNNING', 'ERR_SERVER_NOT_RUNNING'];

const closeSocket = (socket) =>
  new Promise((resolve, reject) => {
    const finish = (error) => {
      if (error && !CLOSED_CODES.includes(error.code)) reject(error);
      else resolve();
    };
    try {
      socket.close(finish);
    } catch (error) {
      finish(error);
    }
  });

const isDatagram = (client) => client.transport.startsWith('udp');

const transportName = (client) =>
  isDatagram(client) ? 'udp' : client.transport;

module.exports = { closeSocket, isDatagram, transportName };
