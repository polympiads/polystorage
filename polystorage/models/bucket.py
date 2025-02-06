import json
import requests
import os
import uuid
from django.db import models
from django.core.exceptions import ValidationError
from polystorage.constants import BUCKET_TYPES
from jose import jws
from django.conf import settings

class Bucket(models.Model):
    objects = models.Manager()  # Default manager

    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    modified_at = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True)
    root_path = models.CharField(max_length=255, editable=False)

    bucket_type = models.CharField(max_length=20, choices=BUCKET_TYPES, default='STANDARD', editable=False)
    external_provider = models.CharField(max_length=255, null=True, blank=True, editable=False)
    cluster = models.CharField(max_length=255, editable=False)  # Cluster is stored as a string

    write_permissions = models.CharField(max_length=1024, blank=True, default='')
    read_permissions = models.CharField(max_length=1024, blank=True, default='')
    delete_permissions = models.CharField(max_length=1024, blank=True, default='')
    mount_permissions = models.CharField(max_length=1024, blank=True, default='')
    observe_permissions = models.CharField(max_length=1024, blank=True, default='')

    mount_enabled = models.BooleanField(default=False)
    observe_enabled = models.BooleanField(default=False)

    class Meta:
        db_table = 'storage_bucket'
        ordering = ['name', 'created_at']

    def clean(self):
        if self.mount_enabled and self.observe_enabled:
            raise ValidationError("A bucket cannot implement both MOUNT and OBSERVE operations")

        if self.bucket_type == 'EXTERNAL':
            if not self.external_provider:
                raise ValidationError("External buckets must specify a provider")

    def save(self, *args, **kwargs):
        is_new = self.pk is None  # Check if it's a new bucket

        if not is_new:
            orig = Bucket.objects.get(pk=self.pk)
            immutable_fields = ['bucket_type', 'external_provider', 'name', 'created_at', 'cluster']
            for field in immutable_fields:
                if getattr(self, field) != getattr(orig, field):
                    raise ValidationError(f"{field} is immutable and cannot be modified")

        self.clean()
        super().save(*args, **kwargs)  # Save first to get the ID

        if is_new:
            self.create_associated_bucket_instance()

    def create_associated_bucket_instance(self):
        # Generate a random folder name
        random_folder = uuid.uuid4().hex[:8]
        # Use the INSTANCES_MAIN_FOLDER setting as the base directory
        base_folder = settings.INSTANCES_MAIN_FOLDER
        # Construct the full root path
        generated_root_path = os.path.join(base_folder, random_folder)

        payload = {
            'name': self.name,
            'root_path': generated_root_path,
            'bucket_type': self.bucket_type,
            'external_provider': self.external_provider,
            'mount_permissions': self.mount_permissions,
        }

        self.root_path = generated_root_path
        self.save(update_fields=['root_path'])

        # Sign the payload using a private key
        private_key = settings.STORAGE_ROOT_PRIVATE_KEY
        signed_payload = jws.sign(payload, private_key, algorithm='RS256')

        # Send the signed payload to the API
        api_url = settings.API_URL + '/api/v1/bucketinst/create/'
        headers = {'Content-Type': 'application/json'}

        response = requests.post(api_url, data=json.dumps({"signed_data": signed_payload}), headers=headers)

        if response.status_code != 200:
            raise Exception(f"Failed to create bucket instance: {response.text}")

    def __str__(self):
        return f"{self.name}"
