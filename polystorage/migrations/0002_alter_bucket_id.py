# Generated by Django 5.1.5 on 2025-02-03 10:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('polystorage', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bucket',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
