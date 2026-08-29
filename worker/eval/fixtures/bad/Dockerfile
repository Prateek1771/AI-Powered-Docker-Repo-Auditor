FROM python:3.8

RUN apt-get update
RUN apt-get install -y curl wget git vim nano gcc build-essential libssl-dev
RUN apt-get install -y openssh-client nmap netcat-openbsd

ADD app.py /app/app.py

RUN pip install flask requests boto3 pytest black flake8 jupyter pandas numpy

ENV SECRET_KEY=mysupersecretkey123
ENV DATABASE_PASSWORD=admin123
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

EXPOSE 22
EXPOSE 80

CMD ["python", "/app/app.py"]
