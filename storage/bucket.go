package storage

import (
	"context"
	"encoding/json"

	gcs "cloud.google.com/go/storage"
)

type Done func(context.Context) error

type Bucket interface {
	Put(context.Context, string, interface{}) error
	Get(context.Context, string, interface{}) (Done, error)
}

type cloudStorage struct {
	bucket *gcs.BucketHandle
}

func (b *cloudStorage) Put(ctx context.Context, key string, value interface{}) error {
	writer := b.bucket.Object(key).NewWriter(ctx)

	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return err
	}

	return writer.Close()
}

func noopDone(context.Context) error {
	return nil
}

func (b *cloudStorage) Get(ctx context.Context, key string, value interface{}) (Done, error) {
	handle := b.bucket.Object(key)

	reader, err := handle.NewReader(ctx)
	if err != nil {
		return noopDone, err
	}

	if err := json.NewDecoder(reader).Decode(value); err != nil {
		return noopDone, err
	}

	if err := reader.Close(); err != nil {
		return noopDone, err
	}

	return func(ctx context.Context) error {
		return handle.Delete(ctx)
	}, nil
}

func NewBucket(name string) (Bucket, error) {
	client, err := gcs.NewClient(context.Background())
	if err != nil {
		return nil, err
	}

	return &cloudStorage{bucket: client.Bucket(name)}, nil
}
