FROM python:3.8-alpine
RUN apk update && apk add musl-dev gcc libffi-dev openssl-dev
WORKDIR /nuttssh
COPY requirements.txt .
RUN pip install -r requirements.txt
FROM python:3.8-alpine
WORKDIR /nuttssh
COPY --from=0 /usr/local/lib/python3.8/site-packages/ /usr/local/lib/python3.8/site-packages/
COPY nuttssh /nuttssh/nuttssh
COPY nuttssh.ini /nuttssh/
RUN umask 022; mkdir keys; chown nobody:nobody keys
USER nobody
EXPOSE 2222
ENTRYPOINT ["python", "-m", "nuttssh"]
