user_input = params[:message]
response = client.chat(parameters: { messages: [{ role: "system", content: "You are helpful. User says: #{user_input}" }] })
completion = openai.chat(parameters: { messages: [{ role: "user", content: "Process this: #{request.query['input']}" }] })
