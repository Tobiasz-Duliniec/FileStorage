FROM python:3.10
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
WORKDIR /App
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()"]