/**
 * Consumes SSE stream over POST.
 * Calls onEvent(eventType, data) for each SSE event received.
 * Calls onComplete() when stream ends.
 * Calls onError(error) on failure.
 */
export async function streamInvestigation({
  trigger,
  investigationId,
  onEvent,
  onComplete,
  onError,
}) {
  try {
    const response = await fetch('/api/investigate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
      },
      body: JSON.stringify({
        trigger,
        investigation_id: investigationId,
      }),
    })

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })

      // SSE format: "event: X\ndata: Y\n\n"
      // Use regex to split on double newlines (Unix or Windows)
      const messages = buffer.split(/\r?\n\r?\n/)
      buffer = messages.pop() // keep incomplete chunk

      for (const message of messages) {
        if (!message.trim()) continue

        const lines = message.split(/\r?\n/)
        let eventType = 'message'
        let data = ''

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            eventType = line.slice(7).trim()
          } else if (line.startsWith('data: ')) {
            data = line.slice(6).trim()
          }
        }

        if (!data) continue

        try {
          const parsed = JSON.parse(data)
          onEvent(eventType, parsed)

          if (eventType === 'complete') {
            onComplete(parsed)
            return
          }
        } catch (e) {
          console.warn('SSE parse error:', e, data)
        }
      }
    }

    onComplete(null)
  } catch (error) {
    onError(error)
  }
}
