const ws = new WebSocket("ws://localhost:8080/")
ws.onopen = () => {
  let count = 0
  setInterval(() => {
    ws.send(`send message count: ${++count}`)
  }, 1000)
}

ws.addEventListener("message", (ev) => {
  if (ev.data instanceof Blob) {
    console.log({
      messageLength: ev.data.size,
      messageType: "binary",
      messageData: ev.data,
    })
  } else {
    console.log({
      messageLength: ev.data.length,
      messageType: "text",
      messageData: ev.data,
    })
  }
})
