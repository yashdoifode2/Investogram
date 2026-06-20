from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
import uuid
import json
import os
import logging
from datetime import datetime

from .models import EmailAnalysis, IOC, EmailReport, AnalysisHistory
from .forms import EmailUploadForm, EmailPasteForm
from .services import (
    EmailParser, HeaderAnalyzer, SPFAnalyzer, 
    DKIMAnalyzer, DMARCAnalyzer, IOCExtractor, ThreatScorer
)
from .services.domain_intelligence import DomainIntelligence
from .services.ip_intelligence import IPIntelligence
from .services.username_discovery import UsernameDiscovery
from .services.social_discovery import SocialDiscovery
from .services.github_intelligence import GitHubIntelligence
from .services.breach_intelligence import BreachIntelligence
from .services.attachment_analyzer import AttachmentAnalyzer

logger = logging.getLogger(__name__)
# Add these imports at the top
from .services.breach_intelligence import BreachIntelligence
from .services.social_discovery import SocialDiscovery
from .services.attachment_analyzer import AttachmentAnalyzer
from .services.username_discovery import UsernameDiscovery

# ============================================
# BREACH INTELLIGENCE VIEW
# ============================================

@login_required
def breach_intelligence(request):
    """Breach intelligence lookup page"""
    result = None
    query = None
    
    if request.method == 'POST':
        query = request.POST.get('query', '').strip()
        search_type = request.POST.get('search_type', 'email')
        
        if query:
            try:
                if search_type == 'email':
                    breach = BreachIntelligence(email=query)
                elif search_type == 'username':
                    breach = BreachIntelligence(username=query)
                elif search_type == 'phone':
                    breach = BreachIntelligence(phone=query)
                else:
                    breach = BreachIntelligence(email=query)
                
                result = breach.get_summary()
                
                # Save to analysis history if email
                if search_type == 'email' and result.get('has_breaches'):
                    # Create a mini analysis record for breach only
                    analysis = EmailAnalysis.objects.create(
                        user=request.user,
                        filename=f"breach_check_{query}.txt",
                        raw_email=f"Breach check for: {query}",
                        parsed_email={'body': f'Breach check for: {query}'},
                        breach_data=result,
                        risk_level=result.get('risk_level', 'LOW'),
                        threat_score=10 if result.get('has_breaches') else 0,
                        status='COMPLETED'
                    )
                    
                    # Add IOCs if breaches found
                    if result.get('has_breaches'):
                        for breach_item in result.get('breaches', []):
                            IOC.objects.create(
                                analysis=analysis,
                                ioc_type='EMAIL' if search_type == 'email' else 'DOMAIN',
                                value=query,
                                context=f"Breach: {breach_item.get('breach_name')} - {breach_item.get('severity')}"
                            )
                
                messages.success(request, f'Breach check completed for {query}')
                
            except Exception as e:
                messages.error(request, f'Error checking breaches: {str(e)}')
    
    context = {
        'result': result,
        'query': query,
        'active_tab': 'breach',
    }
    return render(request, 'email_forensics/breach_intelligence.html', context)

# ============================================
# SOCIAL DISCOVERY VIEW
# ============================================

@login_required
def social_discovery(request):
    """Social profile discovery page"""
    result = None
    query = None
    
    if request.method == 'POST':
        query = request.POST.get('query', '').strip()
        search_type = request.POST.get('search_type', 'username')
        
        if query:
            try:
                if search_type == 'email':
                    # Extract username from email
                    username = query.split('@')[0] if '@' in query else query
                    social = SocialDiscovery(username, query)
                else:
                    social = SocialDiscovery(query)
                
                profiles = social.get_profiles()
                summary = social.get_summary()
                
                result = {
                    'profiles': profiles,
                    'summary': summary,
                    'query': query,
                    'search_type': search_type
                }
                
                # Save to analysis
                analysis = EmailAnalysis.objects.create(
                    user=request.user,
                    filename=f"social_discovery_{query}.txt",
                    raw_email=f"Social discovery for: {query}",
                    parsed_email={'body': f'Social discovery for: {query}'},
                    social_profiles=profiles,
                    status='COMPLETED'
                )
                
                messages.success(request, f'Social discovery completed for {query}')
                
            except Exception as e:
                messages.error(request, f'Error discovering social profiles: {str(e)}')
    
    context = {
        'result': result,
        'query': query,
        'active_tab': 'social',
    }
    return render(request, 'email_forensics/social_discovery.html', context)

# ============================================
# ATTACHMENT ANALYSIS VIEW
# ============================================

@login_required
def attachment_analysis(request, analysis_id):
    """View attachment analysis results"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    attachments = analysis.attachment_findings or []
    
    # Analyze attachments if not already done
    if not attachments and analysis.parsed_email.get('attachments'):
        for attachment in analysis.parsed_email['attachments']:
            try:
                analyzer = AttachmentAnalyzer(attachment)
                attachments.append(analyzer.get_summary())
            except Exception as e:
                logger.warning(f"Attachment analysis failed: {e}")
        analysis.attachment_findings = attachments
        analysis.save()
    
    # Summary statistics
    total_attachments = len(attachments)
    suspicious_count = len([a for a in attachments if a.get('is_suspicious')])
    malicious_count = len([a for a in attachments if a.get('is_malicious')])
    
    context = {
        'analysis': analysis,
        'attachments': attachments,
        'total_attachments': total_attachments,
        'suspicious_count': suspicious_count,
        'malicious_count': malicious_count,
        'active_tab': 'attachments',
    }
    return render(request, 'email_forensics/attachment_analysis.html', context)
# ============================================
# HELPER FUNCTIONS
# ============================================

def extract_domain(from_header):
    """Extract domain from from header"""
    import re
    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        email = email_match.group(1)
    else:
        email = from_header.strip()
    
    if '@' in email:
        return email.split('@')[1].strip()
    return None

def extract_email(from_header):
    """Extract email from from header"""
    import re
    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        return email_match.group(1)
    elif '@' in from_header:
        return from_header.strip()
    return None

# ============================================
# MAIN ANALYSIS FUNCTION
# ============================================

def perform_analysis(analysis):
    """Perform full email analysis with all OSINT services"""
    try:
        # Update status
        analysis.status = 'PROCESSING'
        analysis.save()
        
        # Parse headers
        parsed_email = analysis.parsed_email
        headers = parsed_email.get('headers', {})
        header_analyzer = HeaderAnalyzer(headers)
        
        # Analyze headers
        analysis.headers = {
            'received': header_analyzer.received_headers,
            'route_timeline': header_analyzer.get_route_timeline(),
            'all_ips': header_analyzer.get_all_ips(),
            'origin_ip': header_analyzer.get_origin_ip(),
            'destination_ip': header_analyzer.get_destination_ip(),
        }
        
        # Extract domain from from header
        from_header = parsed_email.get('from', '')
        domain = extract_domain(from_header)
        
        # Extract email from from header
        email = extract_email(from_header)
        
        # Initialize OSINT data
        analysis.osint_data = {}
        analysis.social_profiles = []
        analysis.github_findings = []
        analysis.breach_data = []
        analysis.attachment_findings = []
        analysis.ip_intelligence = []
        
        # ============================================
        # AUTHENTICATION ANALYSIS
        # ============================================
        if domain:
            try:
                # SPF
                spf_analyzer = SPFAnalyzer(domain)
                analysis.spf_result = spf_analyzer.analyze()
                
                # DKIM
                dkim_header = headers.get('dkim-signature', '')
                if dkim_header:
                    dkim_analyzer = DKIMAnalyzer(dkim_header, domain)
                    analysis.dkim_result = dkim_analyzer.verify()
                
                # DMARC
                dmarc_analyzer = DMARCAnalyzer(domain)
                analysis.dmarc_result = dmarc_analyzer.analyze()
                
            except Exception as e:
                logger.warning(f"Authentication analysis failed: {e}")
        
        # ============================================
        # DOMAIN INTELLIGENCE
        # ============================================
        if domain:
            try:
                domain_intel = DomainIntelligence(domain)
                analysis.domain_intelligence = domain_intel.analyze()
            except Exception as e:
                logger.warning(f"Domain intelligence failed: {e}")
        
        # ============================================
        # IP INTELLIGENCE
        # ============================================
        all_ips = header_analyzer.get_all_ips()
        ip_intelligence = []
        for ip in all_ips[:5]:  # Limit to 5 IPs
            try:
                ip_intel = IPIntelligence(ip)
                ip_intelligence.append(ip_intel.analyze())
            except Exception as e:
                logger.warning(f"IP intelligence failed for {ip}: {e}")
        analysis.ip_intelligence = ip_intelligence
        
        # ============================================
        # USERNAME DISCOVERY
        # ============================================
        if email:
            try:
                username_discovery = UsernameDiscovery(email)
                analysis.osint_data['usernames'] = username_discovery.get_variations()
                analysis.osint_data['username_variations'] = username_discovery.variations
            except Exception as e:
                logger.warning(f"Username discovery failed: {e}")
        
        # ============================================
        # SOCIAL PROFILE DISCOVERY
        # ============================================
        if email:
            try:
                username = email.split('@')[0] if '@' in email else email
                social_discovery = SocialDiscovery(username, email)
                analysis.social_profiles = social_discovery.get_profiles()
                analysis.osint_data['social_summary'] = social_discovery.get_summary()
            except Exception as e:
                logger.warning(f"Social discovery failed: {e}")
        
        # ============================================
        # GITHUB INTELLIGENCE
        # ============================================
        if email or domain:
            try:
                github = GitHubIntelligence(
                    username=email.split('@')[0] if email else None,
                    email=email,
                    domain=domain
                )
                analysis.github_findings = github.get_data()
                analysis.osint_data['github_summary'] = github.get_summary()
            except Exception as e:
                logger.warning(f"GitHub intelligence failed: {e}")
        
        # ============================================
        # BREACH INTELLIGENCE
        # ============================================
        if email:
            try:
                breach = BreachIntelligence(email=email)
                analysis.breach_data = breach.get_summary()
                analysis.osint_data['breach_summary'] = breach.get_summary()
            except Exception as e:
                logger.warning(f"Breach intelligence failed: {e}")
        
        # ============================================
        # ATTACHMENT ANALYSIS
        # ============================================
        attachments = parsed_email.get('attachments', [])
        attachment_findings = []
        for attachment in attachments:
            try:
                analyzer = AttachmentAnalyzer(attachment)
                attachment_findings.append(analyzer.get_summary())
            except Exception as e:
                logger.warning(f"Attachment analysis failed: {e}")
        analysis.attachment_findings = attachment_findings
        
        # ============================================
        # IOC EXTRACTION
        # ============================================
        try:
            ioc_extractor = IOCExtractor(parsed_email)
            iocs = ioc_extractor.extract_all()
            for ioc in iocs:
                IOC.objects.create(
                    analysis=analysis,
                    ioc_type=ioc['type'],
                    value=ioc['value'],
                    context=ioc.get('context', '')
                )
        except Exception as e:
            logger.warning(f"IOC extraction failed: {e}")
        
        # ============================================
        # THREAT SCORING
        # ============================================
        try:
            scorer = ThreatScorer(analysis)
            threat_score = scorer.calculate_score()
            analysis.threat_score = threat_score['score']
            analysis.risk_level = threat_score['level']
            
            # Store threat indicators
            analysis.osint_data['threat_indicators'] = threat_score.get('indicators', [])
        except Exception as e:
            logger.warning(f"Threat scoring failed: {e}")
        
        # ============================================
        # GRAVATAR INTELLIGENCE
        # ============================================
        if email:
            try:
                import hashlib
                email_hash = hashlib.md5(email.lower().encode()).hexdigest()
                gravatar_url = f"https://www.gravatar.com/{email_hash}"
                
                # Check if Gravatar exists
                import requests
                response = requests.head(f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=5)
                if response.status_code == 200:
                    analysis.osint_data['gravatar'] = {
                        'exists': True,
                        'url': f"https://www.gravatar.com/avatar/{email_hash}?s=200",
                        'profile_url': f"https://www.gravatar.com/{email_hash}"
                    }
                else:
                    analysis.osint_data['gravatar'] = {
                        'exists': False,
                        'url': None
                    }
            except Exception as e:
                logger.warning(f"Gravatar check failed: {e}")
        
        # Update status
        analysis.status = 'COMPLETED'
        analysis.save()
        
        # Log history
        AnalysisHistory.objects.create(
            analysis=analysis,
            user=analysis.user,
            action='COMPLETE',
            details={
                'score': analysis.threat_score,
                'level': analysis.risk_level,
                'iocs_count': IOC.objects.filter(analysis=analysis).count()
            }
        )
        
        return analysis
        
    except Exception as e:
        analysis.status = 'FAILED'
        analysis.error_message = str(e)
        analysis.save()
        
        AnalysisHistory.objects.create(
            analysis=analysis,
            user=analysis.user,
            action='FAILED',
            details={'error': str(e)}
        )
        
        logger.error(f"Analysis failed: {e}")
        raise

# ============================================
# DASHBOARD VIEWS
# ============================================

@login_required
def dashboard(request):
    """Email Forensics Dashboard"""
    user = request.user
    
    # Statistics
    total_analyses = EmailAnalysis.objects.filter(user=user).count()
    critical_risk = EmailAnalysis.objects.filter(user=user, risk_level='CRITICAL').count()
    high_risk = EmailAnalysis.objects.filter(user=user, risk_level='HIGH').count()
    medium_risk = EmailAnalysis.objects.filter(user=user, risk_level='MEDIUM').count()
    low_risk = EmailAnalysis.objects.filter(user=user, risk_level='LOW').count()
    
    recent_analyses = EmailAnalysis.objects.filter(user=user)[:10]
    
    # Get risk distribution for chart
    risk_distribution = {
        'CRITICAL': critical_risk,
        'HIGH': high_risk,
        'MEDIUM': medium_risk,
        'LOW': low_risk
    }
    
    context = {
        'total_analyses': total_analyses,
        'critical_risk': critical_risk,
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'risk_distribution': risk_distribution,
        'recent_analyses': recent_analyses,
        'active_tab': 'dashboard',
    }
    return render(request, 'email_forensics/dashboard.html', context)

# ============================================
# ANALYSIS VIEWS
# ============================================

@login_required
def analyze_email(request):
    """Upload or paste email for analysis"""
    upload_form = EmailUploadForm()
    paste_form = EmailPasteForm()
    analysis = None
    
    if request.method == 'POST':
        if 'upload_file' in request.POST:
            upload_form = EmailUploadForm(request.POST, request.FILES)
            if upload_form.is_valid():
                email_file = request.FILES['file']
                
                # Validate file type
                filename = email_file.name.lower()
                if not (filename.endswith('.eml') or filename.endswith('.msg')):
                    messages.error(request, 'Please upload .eml or .msg files only')
                    return render(request, 'email_forensics/analyze.html', {
                        'upload_form': upload_form,
                        'paste_form': paste_form,
                        'active_tab': 'analyze',
                    })
                
                try:
                    # Parse email
                    parser = EmailParser()
                    content = email_file.read()
                    parsed = parser.parse_bytes(content)
                    
                    # Create analysis record
                    analysis = EmailAnalysis.objects.create(
                        user=request.user,
                        filename=email_file.name,
                        raw_email=content.decode('utf-8', errors='ignore'),
                        parsed_email=parsed,
                        status='PROCESSING'
                    )
                    
                    # Perform analysis
                    perform_analysis(analysis)
                    
                    messages.success(request, f'✅ Email "{email_file.name}" analyzed successfully!')
                    return redirect('email_forensics:analysis_result', analysis_id=analysis.id)
                    
                except Exception as e:
                    messages.error(request, f'❌ Error analyzing email: {str(e)}')
        
        elif 'paste_content' in request.POST:
            paste_form = EmailPasteForm(request.POST)
            if paste_form.is_valid():
                email_content = paste_form.cleaned_data['email_content']
                
                if not email_content.strip():
                    messages.error(request, 'Please paste email content')
                    return render(request, 'email_forensics/analyze.html', {
                        'upload_form': upload_form,
                        'paste_form': paste_form,
                        'active_tab': 'analyze',
                    })
                
                try:
                    # Parse email
                    parser = EmailParser()
                    parsed = parser.parse_text(email_content)
                    
                    # Create analysis record
                    analysis = EmailAnalysis.objects.create(
                        user=request.user,
                        filename='pasted_email.txt',
                        raw_email=email_content,
                        parsed_email=parsed,
                        status='PROCESSING'
                    )
                    
                    # Perform analysis
                    perform_analysis(analysis)
                    
                    messages.success(request, '✅ Email analyzed successfully!')
                    return redirect('email_forensics:analysis_result', analysis_id=analysis.id)
                    
                except Exception as e:
                    messages.error(request, f'❌ Error analyzing email: {str(e)}')
    
    context = {
        'upload_form': upload_form,
        'paste_form': paste_form,
        'active_tab': 'analyze',
    }
    return render(request, 'email_forensics/analyze.html', context)

# ============================================
# RESULT VIEWS
# ============================================

@login_required
def analysis_result(request, analysis_id):
    """View analysis results"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    
    # Get IOCs
    iocs = IOC.objects.filter(analysis=analysis)
    
    context = {
        'analysis': analysis,
        'iocs': iocs,
        'active_tab': 'history',
    }
    return render(request, 'email_forensics/result_detail.html', context)

@login_required
def analysis_history(request):
    """View analysis history"""
    analyses = EmailAnalysis.objects.filter(user=request.user)
    
    # Apply filters
    search = request.GET.get('search')
    if search:
        analyses = analyses.filter(
            models.Q(filename__icontains=search) |
            models.Q(parsed_email__subject__icontains=search) |
            models.Q(parsed_email__from__icontains=search)
        )
    
    risk_level = request.GET.get('risk_level')
    if risk_level:
        analyses = analyses.filter(risk_level=risk_level)
    
    paginator = Paginator(analyses, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'risk_level': risk_level,
        'risk_levels': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        'active_tab': 'history',
    }
    return render(request, 'email_forensics/history.html', context)

@login_required
def delete_analysis(request, analysis_id):
    """Delete an analysis"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    
    if request.method == 'POST':
        # Delete related IOCs
        IOC.objects.filter(analysis=analysis).delete()
        analysis.delete()
        messages.success(request, 'Analysis deleted successfully')
        return redirect('email_forensics:analysis_history')
    
    return redirect('email_forensics:analysis_history')

# ============================================
# REPORT VIEWS
# ============================================

@login_required
def generate_report(request, analysis_id):
    """Generate report for analysis"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    
    if request.method == 'POST':
        try:
            from .services.report_generator import ReportGenerator
            generator = ReportGenerator()
            report = generator.generate_pdf(analysis, request.user)
            
            # Log report generation
            AnalysisHistory.objects.create(
                analysis=analysis,
                user=request.user,
                action='REPORT',
                details={'report_id': report.id, 'format': 'PDF'}
            )
            
            messages.success(request, '✅ Report generated successfully!')
            return redirect('email_forensics:download_report', report_id=report.id)
            
        except Exception as e:
            messages.error(request, f'❌ Error generating report: {str(e)}')
    
    context = {
        'analysis': analysis,
        'active_tab': 'history',
    }
    return render(request, 'email_forensics/report_preview.html', context)

@login_required
def download_report(request, report_id):
    """Download generated report"""
    report = get_object_or_404(EmailReport, id=report_id, user=request.user)
    
    # Increment download count
    report.download_count += 1
    report.save()
    
    # Log download
    AnalysisHistory.objects.create(
        analysis=report.analysis,
        user=request.user,
        action='DOWNLOAD',
        details={'report_id': report.id}
    )
    
    # Get file path
    file_path = os.path.join(settings.MEDIA_ROOT, report.file_path)
    
    if not os.path.exists(file_path):
        messages.error(request, "Report file not found")
        return redirect('email_forensics:analysis_history')
    
    with open(file_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="forensic_report_{report.analysis.id}.pdf"'
        return response

# ============================================
# IOC VIEWS
# ============================================

@login_required
def view_iocs(request, analysis_id):
    """View IOCs from analysis"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    iocs = IOC.objects.filter(analysis=analysis)
    
    # Group by type
    iocs_by_type = {}
    for ioc in iocs:
        type_name = ioc.get_ioc_type_display()
        if type_name not in iocs_by_type:
            iocs_by_type[type_name] = []
        iocs_by_type[type_name].append(ioc)
    
    context = {
        'analysis': analysis,
        'iocs': iocs,
        'iocs_by_type': iocs_by_type,
        'active_tab': 'history',
    }
    return render(request, 'email_forensics/iocs.html', context)

@login_required
def export_iocs(request, analysis_id):
    """Export IOCs in various formats"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    iocs = IOC.objects.filter(analysis=analysis)
    
    format_type = request.GET.get('format', 'json')
    
    if format_type == 'json':
        data = {
            'analysis_id': str(analysis.id),
            'filename': analysis.filename,
            'total_iocs': iocs.count(),
            'iocs': [
                {
                    'type': ioc.get_ioc_type_display(),
                    'value': ioc.value,
                    'is_malicious': ioc.is_malicious,
                    'context': ioc.context
                } for ioc in iocs
            ]
        }
        return JsonResponse(data, safe=False)
    
    elif format_type == 'csv':
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="iocs_{analysis.id}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Type', 'Value', 'Malicious', 'Context'])
        for ioc in iocs:
            writer.writerow([
                ioc.get_ioc_type_display(),
                ioc.value,
                'Yes' if ioc.is_malicious else 'No',
                ioc.context
            ])
        
        return response
    
    return JsonResponse({'error': 'Invalid format'}, status=400)

# ============================================
# OSINT VIEWS
# ============================================

@login_required
def osint_lookup(request):
    """Perform OSINT lookup on email or domain"""
    query = request.GET.get('query')
    query_type = request.GET.get('type', 'email')
    
    if not query:
        return JsonResponse({'error': 'Query required'}, status=400)
    
    result = {}
    
    if query_type == 'email':
        # Email OSINT
        email = query
        
        # Username discovery
        username_discovery = UsernameDiscovery(email)
        result['usernames'] = username_discovery.get_variations()
        
        # Social discovery
        username = email.split('@')[0] if '@' in email else email
        social_discovery = SocialDiscovery(username, email)
        result['social_profiles'] = social_discovery.get_profiles()
        
        # Breach intelligence
        breach = BreachIntelligence(email=email)
        result['breaches'] = breach.get_summary()
        
        # GitHub intelligence
        github = GitHubIntelligence(email=email)
        result['github'] = github.get_summary()
        
        # Gravatar
        import hashlib
        import requests
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        try:
            response = requests.head(f"https://www.gravatar.com/avatar/{email_hash}?d=404", timeout=5)
            result['gravatar'] = {
                'exists': response.status_code == 200,
                'url': f"https://www.gravatar.com/avatar/{email_hash}?s=200" if response.status_code == 200 else None
            }
        except:
            result['gravatar'] = {'exists': False}
    
    elif query_type == 'domain':
        # Domain OSINT
        domain = query
        domain_intel = DomainIntelligence(domain)
        result['domain'] = domain_intel.analyze()
        
        # GitHub domain search
        github = GitHubIntelligence(domain=domain)
        result['github'] = github.get_summary()
    
    return JsonResponse(result)

# ============================================
# API VIEWS
# ============================================

@login_required
@require_http_methods(["POST"])
def api_analyze_email(request):
    """API endpoint for email analysis"""
    try:
        # Check if file or text
        if request.FILES.get('file'):
            email_file = request.FILES['file']
            
            # Validate file type
            filename = email_file.name.lower()
            if not (filename.endswith('.eml') or filename.endswith('.msg')):
                return JsonResponse({'error': 'Only .eml and .msg files are supported'}, status=400)
            
            parser = EmailParser()
            content = email_file.read()
            parsed = parser.parse_bytes(content)
            
            analysis = EmailAnalysis.objects.create(
                user=request.user,
                filename=email_file.name,
                raw_email=content.decode('utf-8', errors='ignore'),
                parsed_email=parsed,
                status='PROCESSING'
            )
        elif request.POST.get('email_text'):
            email_text = request.POST['email_text']
            parser = EmailParser()
            parsed = parser.parse_text(email_text)
            
            analysis = EmailAnalysis.objects.create(
                user=request.user,
                filename='api_email.txt',
                raw_email=email_text,
                parsed_email=parsed,
                status='PROCESSING'
            )
        else:
            return JsonResponse({'error': 'No file or email text provided'}, status=400)
        
        # Perform analysis
        perform_analysis(analysis)
        
        # Get IOCs
        iocs = IOC.objects.filter(analysis=analysis)
        
        return JsonResponse({
            'analysis_id': str(analysis.id),
            'status': 'success',
            'risk_level': analysis.risk_level,
            'threat_score': analysis.threat_score,
            'iocs_count': iocs.count(),
            'iocs': [
                {
                    'type': ioc.get_ioc_type_display(),
                    'value': ioc.value,
                    'is_malicious': ioc.is_malicious
                } for ioc in iocs[:20]
            ],
            'domain_intelligence': analysis.domain_intelligence,
            'breach_data': analysis.breach_data,
            'created_at': analysis.created_at.isoformat()
        })
        
    except Exception as e:
        logger.error(f"API analysis failed: {e}")
        return JsonResponse({'error': str(e)}, status=500)

# ============================================
# EXPORT VIEWS
# ============================================

@login_required
def export_analysis(request, analysis_id):
    """Export analysis results in various formats"""
    analysis = get_object_or_404(EmailAnalysis, id=analysis_id, user=request.user)
    format_type = request.GET.get('format', 'json')
    
    if format_type == 'json':
        data = {
            'id': str(analysis.id),
            'filename': analysis.filename,
            'created_at': analysis.created_at.isoformat(),
            'risk_level': analysis.risk_level,
            'threat_score': analysis.threat_score,
            'parsed_email': analysis.parsed_email,
            'headers': analysis.headers,
            'spf_result': analysis.spf_result,
            'dkim_result': analysis.dkim_result,
            'dmarc_result': analysis.dmarc_result,
            'domain_intelligence': analysis.domain_intelligence,
            'ip_intelligence': analysis.ip_intelligence,
            'url_findings': analysis.url_findings,
            'attachment_findings': analysis.attachment_findings,
            'iocs': [
                {
                    'type': ioc.get_ioc_type_display(),
                    'value': ioc.value,
                    'is_malicious': ioc.is_malicious,
                    'context': ioc.context
                } for ioc in IOC.objects.filter(analysis=analysis)
            ],
            'osint_data': analysis.osint_data,
            'social_profiles': analysis.social_profiles,
            'github_findings': analysis.github_findings,
            'breach_data': analysis.breach_data,
        }
        return JsonResponse(data, safe=False)
    
    elif format_type == 'csv':
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="analysis_{analysis.id}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Field', 'Value'])
        writer.writerow(['Analysis ID', str(analysis.id)])
        writer.writerow(['Filename', analysis.filename])
        writer.writerow(['Risk Level', analysis.risk_level])
        writer.writerow(['Threat Score', analysis.threat_score])
        writer.writerow(['Created', analysis.created_at.isoformat()])
        writer.writerow([])
        writer.writerow(['IOCs'])
        writer.writerow(['Type', 'Value', 'Malicious'])
        for ioc in IOC.objects.filter(analysis=analysis):
            writer.writerow([
                ioc.get_ioc_type_display(),
                ioc.value,
                'Yes' if ioc.is_malicious else 'No'
            ])
        
        return response
    
    return JsonResponse({'error': 'Invalid format'}, status=400)