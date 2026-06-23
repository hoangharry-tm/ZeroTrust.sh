user_input = params[:message]
response = client.chat(parameters: {
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user", content: user_input }
  ]
})
