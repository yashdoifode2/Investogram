from django import forms

class EmailUploadForm(forms.Form):
    file = forms.FileField(
        label='Upload Email File',
        help_text='Supported formats: .eml, .msg',
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.eml,.msg'
        })
    )

class EmailPasteForm(forms.Form):
    email_content = forms.CharField(
        label='Paste Email Content',
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 15,
            'placeholder': 'Paste the full email content including headers...'
        }),
        help_text='Paste the complete email with headers'
    )