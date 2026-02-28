from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanresult",
            name="evidence",
            field=models.TextField(blank=True, default=""),
            preserve_default=False,
        ),
    ]
