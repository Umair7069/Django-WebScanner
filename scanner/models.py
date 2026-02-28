from django.db import models

class Target(models.Model):
    url = models.URLField()

    def __str__(self):
        return self.url


class ScanResult(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    vulnerability_type = models.CharField(max_length=50)
    payload_used = models.TextField()
    vulnerable_page = models.TextField()
    is_vulnerable = models.BooleanField(default=False)
    response = models.TextField()
    evidence = models.TextField(blank=True)

    def __str__(self):
        return f"{self.vulnerability_type} on {self.target.url}"
