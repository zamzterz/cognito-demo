def list_bucket(session, bucket_name, prefix=None):
    s3 = session.resource('s3')
    bucket = s3.Bucket(bucket_name)
    if prefix:
        return bucket.objects.filter(Prefix=prefix)

    return bucket.objects.all()
