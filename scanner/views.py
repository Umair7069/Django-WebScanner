from django.shortcuts import render, redirect
from .models import Target, ScanResult
from . import scanner

def index(request):
    if request.method == "POST":
        url = request.POST.get("url")
        # which tests to run: user can select one or both
        run_xss = True if request.POST.get('test_xss') == 'on' else False
        run_sqli = True if request.POST.get('test_sqli') == 'on' else False
        # optional authentication value (cookie only)
        cookie = request.POST.get('cookie')

        if url:
            # Save target
            target = Target.objects.create(url=url)

            # Run scanner
            findings = scanner.scan_target(url, run_xss=run_xss, run_sqli=run_sqli,
                                          cookie_header=cookie)

            # Save results
            for f in findings:
                ScanResult.objects.create(
                    target=target,
                    vulnerability_type=f.get('vuln_type'),
                    payload_used=f.get('payload', ''),
                    vulnerable_page=f.get('url'),
                    is_vulnerable=True,  # mark as vulnerable if a finding exists
                    # keep `response` for the vulnerable parameter (so it shows in the Response column)
                    response=f.get('parameter', ''),
                    # store strong evidence in its own field
                    evidence=f.get('evidence', '')
                )

            return redirect('results', target_id=target.id)

    return render(request, "scanner/index.html")


def results(request, target_id):
    target = Target.objects.get(id=target_id)
    results = target.scanresult_set.all().order_by('-id')
    return render(request, "scanner/results.html", {"target": target, "results": results})