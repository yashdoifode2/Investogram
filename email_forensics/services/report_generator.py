"""
Report Generator - Generates professional PDF reports
"""

import os
import json
from datetime import datetime
from django.conf import settings
from django.template.loader import render_to_string
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from ..models import EmailReport

class ReportGenerator:
    """Generate professional forensic reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00d4ff'),
            alignment=TA_CENTER,
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#00d4ff'),
            spaceAfter=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#e8edf5'),
            spaceAfter=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#00d4aa'),
            fontSize=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#ffa502'),
            fontSize=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#ff4757'),
            fontSize=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#ff0000'),
            fontSize=12
        ))
    
    def generate_pdf(self, analysis, user):
        """Generate PDF report for an analysis"""
        # Create buffer
        import io
        buffer = io.BytesIO()
        
        # Create document
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )
        
        story = []
        
        # Title
        story.append(Paragraph("Email Forensics & OSINT Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        risk_color = self._get_risk_color(analysis.risk_level)
        story.append(Paragraph(
            f"<b>Risk Level:</b> <font color='{risk_color}'>{analysis.risk_level}</font>",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            f"<b>Threat Score:</b> {analysis.threat_score}/100",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            f"<b>Analysis Date:</b> {analysis.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 20))
        
        # Email Metadata
        story.append(Paragraph("Email Metadata", self.styles['CustomHeading']))
        parsed = analysis.parsed_email
        metadata = [
            ('From', parsed.get('from', 'N/A')),
            ('To', parsed.get('to', 'N/A')),
            ('Subject', parsed.get('subject', 'N/A')),
            ('Date', parsed.get('date', 'N/A')),
            ('Message-ID', parsed.get('message_id', 'N/A')),
            ('Reply-To', parsed.get('reply_to', 'N/A')),
        ]
        story.extend(self._create_table(metadata))
        story.append(Spacer(1, 20))
        
        # Authentication Results
        story.append(Paragraph("Authentication Analysis", self.styles['CustomHeading']))
        
        # SPF
        if analysis.spf_result:
            spf = analysis.spf_result
            story.append(Paragraph("SPF Analysis", self.styles['CustomHeading3']))
            spf_data = [
                ('Result', spf.get('result', 'N/A')),
                ('Explanation', spf.get('explanation', 'N/A')),
                ('Risk', spf.get('risk', 'N/A')),
            ]
            story.extend(self._create_table(spf_data))
            story.append(Spacer(1, 10))
        
        # DKIM
        if analysis.dkim_result:
            dkim = analysis.dkim_result
            story.append(Paragraph("DKIM Analysis", self.styles['CustomHeading3']))
            dkim_data = [
                ('Valid', 'Yes' if dkim.get('valid') else 'No'),
                ('Signing Domain', dkim.get('signing_domain', 'N/A')),
                ('Selector', dkim.get('selector', 'N/A')),
                ('Algorithm', dkim.get('algorithm', 'N/A')),
                ('Risk', dkim.get('risk', 'N/A')),
            ]
            story.extend(self._create_table(dkim_data))
            story.append(Spacer(1, 10))
        
        # DMARC
        if analysis.dmarc_result:
            dmarc = analysis.dmarc_result
            story.append(Paragraph("DMARC Analysis", self.styles['CustomHeading3']))
            dmarc_data = [
                ('Policy', dmarc.get('policy', 'N/A')),
                ('Subdomain Policy', dmarc.get('subdomain_policy', 'N/A')),
                ('Risk', dmarc.get('risk', 'N/A')),
            ]
            story.extend(self._create_table(dmarc_data))
            story.append(Spacer(1, 20))
        
        # Domain Intelligence
        if analysis.domain_intelligence:
            story.append(Paragraph("Domain Intelligence", self.styles['CustomHeading']))
            domain = analysis.domain_intelligence
            domain_data = [
                ('Domain', domain.get('domain', 'N/A')),
                ('Registrar', domain.get('registrar', 'N/A')),
                ('Registration Date', domain.get('registration_date', 'N/A')),
                ('Expiry Date', domain.get('expiry_date', 'N/A')),
                ('Domain Age', f"{domain.get('age_years', 0)} years"),
                ('Suspicious', 'Yes' if domain.get('is_suspicious') else 'No'),
            ]
            story.extend(self._create_table(domain_data))
            story.append(Spacer(1, 20))
        
        # IP Intelligence
        if analysis.ip_intelligence:
            story.append(Paragraph("IP Intelligence", self.styles['CustomHeading']))
            for ip_data in analysis.ip_intelligence[:5]:  # Limit to 5
                ip_info = [
                    ('IP Address', ip_data.get('ip', 'N/A')),
                    ('Country', ip_data.get('country', 'N/A')),
                    ('City', ip_data.get('city', 'N/A')),
                    ('ISP', ip_data.get('isp', 'N/A')),
                    ('Suspicious', 'Yes' if ip_data.get('is_suspicious') else 'No'),
                ]
                story.extend(self._create_table(ip_info))
                story.append(Spacer(1, 5))
            story.append(Spacer(1, 10))
        
        # IOCs
        iocs = analysis.ioc_objects.all()
        if iocs:
            story.append(Paragraph("Indicators of Compromise (IOCs)", self.styles['CustomHeading']))
            ioc_data = [['Type', 'Value', 'Context']]
            for ioc in iocs[:20]:  # Limit to 20
                ioc_data.append([
                    ioc.get_ioc_type_display(),
                    ioc.value,
                    ioc.context[:50] if ioc.context else ''
                ])
            story.extend(self._create_table(ioc_data))
            story.append(Spacer(1, 20))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment", self.styles['CustomHeading']))
        story.append(Paragraph(
            f"<b>Overall Risk Level:</b> <font color='{risk_color}'>{analysis.risk_level}</font>",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            f"<b>Threat Score:</b> {analysis.threat_score}/100",
            self.styles['Normal']
        ))
        story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['CustomHeading']))
        recommendations = self._generate_recommendations(analysis)
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 30))
        
        # Footer
        story.append(Paragraph(
            "This report is for authorized use only.",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            f"Generated by Cyber Intel Platform - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['Normal']
        ))
        
        # Build PDF
        doc.build(story)
        
        # Get PDF content
        pdf_content = buffer.getvalue()
        buffer.close()
        
        # Save to file
        filename = f"forensic_report_{analysis.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = os.path.join(settings.MEDIA_ROOT, 'reports', filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'wb') as f:
            f.write(pdf_content)
        
        # Create report record
        report = EmailReport.objects.create(
            analysis=analysis,
            user=user,
            file_path=os.path.join('reports', filename),
            file_size=len(pdf_content),
            format='PDF'
        )
        
        return report
    
    def _create_table(self, data):
        """Create a table from data"""
        table = Table(data, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a2332')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#e8edf5')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#0d1520')),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#e8edf5')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#2a3a4a')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        return [table, Spacer(1, 6)]
    
    def _get_risk_color(self, risk_level):
        """Get color for risk level"""
        colors_map = {
            'LOW': '#00d4aa',
            'MEDIUM': '#ffa502',
            'HIGH': '#ff4757',
            'CRITICAL': '#ff0000',
        }
        return colors_map.get(risk_level, '#888888')
    
    def _generate_recommendations(self, analysis):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # SPF recommendations
        if analysis.spf_result:
            spf = analysis.spf_result
            if spf.get('result') in ['FAIL', 'SOFTFAIL']:
                recommendations.append('Review SPF configuration - current policy is too permissive')
            elif not spf.get('record_exists'):
                recommendations.append('Publish SPF record to prevent email spoofing')
        
        # DKIM recommendations
        if analysis.dkim_result:
            dkim = analysis.dkim_result
            if not dkim.get('valid'):
                if dkim.get('error') == 'No DKIM signature found':
                    recommendations.append('Implement DKIM signing to improve email authentication')
                else:
                    recommendations.append('Fix DKIM configuration - signature verification failed')
        
        # DMARC recommendations
        if analysis.dmarc_result:
            dmarc = analysis.dmarc_result
            if dmarc.get('policy') in ['NONE']:
                recommendations.append('Implement DMARC policy with p=quarantine or p=reject')
            elif not dmarc.get('record_exists'):
                recommendations.append('Publish DMARC record to protect against spoofing')
        
        # Domain recommendations
        if analysis.domain_intelligence:
            domain = analysis.domain_intelligence
            if domain.get('is_suspicious'):
                recommendations.append('Domain shows suspicious characteristics - investigate further')
        
        # General recommendations
        if analysis.risk_level in ['HIGH', 'CRITICAL']:
            recommendations.append('This email shows high-risk indicators - exercise caution')
            recommendations.append('Do not click any links or open attachments without verification')
        
        if not recommendations:
            recommendations.append('No critical issues found. Continue monitoring for suspicious activity.')
        
        return recommendations