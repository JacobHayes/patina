# A minimal ASGI app for uvicorn.
async def app(scope, receive, send):
    if scope['type'] == 'lifespan':
        while True:
            m = await receive()
            if m['type'] == 'lifespan.startup': await send({'type': 'lifespan.startup.complete'})
            elif m['type'] == 'lifespan.shutdown': await send({'type': 'lifespan.shutdown.complete'}); return
    body = b''
    while True:
        m = await receive(); body += m.get('body', b'')
        if not m.get('more_body'): break
    await send({'type': 'http.response.start', 'status': 200, 'headers': [(b'content-type', b'text/plain')]})
    await send({'type': 'http.response.body', 'body': b'echo:' + scope['path'].encode() + b':' + str(len(body)).encode()})
