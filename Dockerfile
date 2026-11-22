FROM python:3.10-slim
RUN mkdir FileStorage
COPY . /FileStorage
WORKDIR /FileStorage
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /FileStorage/App
EXPOSE 5000
RUN ls
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()"]