def list_bucket(session, bucket_name):
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    return bucket.objects.all()
