import net from "node:net";

export class VpnControl {
  constructor(socketPath) {
    this.socketPath = socketPath;
  }

  command(command) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let response = "";
      socket.setEncoding("utf8");
      socket.setTimeout(2500);
      socket.on("connect", () => socket.end(`${command}\n`));
      socket.on("data", (chunk) => { response += chunk; });
      socket.on("end", () => {
        try { resolve(JSON.parse(response.trim())); } catch (error) { reject(error); }
      });
      socket.on("timeout", () => socket.destroy(new Error("VPN control socket timed out")));
      socket.on("error", reject);
    });
  }

  watch(onMessage, onError, onClose = () => {}) {
    const socket = net.createConnection(this.socketPath);
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write("WATCH\n"));
    socket.on("data", (chunk) => {
      buffer += chunk;
      while (buffer.includes("\n")) {
        const index = buffer.indexOf("\n");
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (line) {
          try { onMessage(JSON.parse(line)); } catch (error) { onError(error); }
        }
      }
    });
    socket.on("error", onError);
    socket.on("close", onClose);
    return socket;
  }
}
