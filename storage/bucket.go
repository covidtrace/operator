package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	gcs "cloud.google.com/go/storage"
)

type Bucket interface {
	Get(context.Context, string) (io.ReadCloser, error)
	Put(context.Context, string, io.Reader) error
	Delete(context.Context, string) (bool, error)
}

type JSONBucket interface {
	Bucket
	GetJSON(context.Context, string, interface{}) (bool, error)
	PutJSON(context.Context, string, interface{}) error
}

type cloudStorage struct {
	bucket *gcs.BucketHandle
}

func (b *cloudStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	reader, err := b.bucket.Object(key).NewReader(ctx)
	if err != nil {
		if err == gcs.ErrObjectNotExist {
			return nil, nil
		}

		return nil, err
	}

	return reader, nil
}

func (b *cloudStorage) GetJSON(ctx context.Context, key string, value interface{}) (bool, error) {
	reader, err := b.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if reader == nil {
		return false, nil
	}

	if err := json.NewDecoder(reader).Decode(value); err != nil {
		return true, err
	}

	return true, reader.Close()
}

func (b *cloudStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	writer := b.bucket.Object(key).NewWriter(ctx)
	if _, err := io.Copy(writer, reader); err != nil {
		return err
	}

	return writer.Close()
}

func (b *cloudStorage) PutJSON(ctx context.Context, key string, value interface{}) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(value); err != nil {
		return err
	}

	return b.Put(ctx, key, &buf)
}

func (b *cloudStorage) Delete(ctx context.Context, key string) (bool, error) {
	if err := b.bucket.Object(key).Delete(ctx); err != nil {
		if err == gcs.ErrObjectNotExist {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

func NewJSONBucket(name string) (JSONBucket, error) {
	client, err := gcs.NewClient(context.Background())
	if err != nil {
		return nil, err
	}

	return &cloudStorage{bucket: client.Bucket(name)}, nil
}

func NewBucket(name string) (Bucket, error) {
	return NewJSONBucket(name)
}
