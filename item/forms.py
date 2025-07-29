from django import forms
from .models import Item

# Define common classes for styling
INPUT_CLASSES = 'w-full py-4 px-6 rounded-xl border'
CHECKBOX_CLASSES = 'border'
SELECT_CLASSES = 'w-full py-4 px-6 rounded-xl border'

class NewItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = ('Category', 'name', 'location', 'description', 'price', 'image', 'phone_number', 'email', 'is_available', 'is_negotiable', 'facebook', 'instagram', 'qr')

        widgets = {
            'Category': forms.Select(attrs={'class': SELECT_CLASSES}),
            'name': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Name'}),
            'location': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Location'}),
            'description': forms.Textarea(attrs={'class': f'{INPUT_CLASSES} resize-none', 'placeholder': 'Enter post description'}),  
            'price': forms.NumberInput(attrs={'class': f'{INPUT_CLASSES} text-green-500', 'placeholder': 'Enter Price per Day'}),
            'image': forms.ClearableFileInput(attrs={'class': f'{INPUT_CLASSES} bg-blue-500 text-white'}),
            'phone_number': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter phonenumber'}),
            'email': forms.EmailInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter email'}),
            'is_available': forms.CheckboxInput(attrs={'class': CHECKBOX_CLASSES}),
            'is_negotiable': forms.CheckboxInput(attrs={'class': CHECKBOX_CLASSES}),
            'facebook': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Facebook link'}),
            'instagram': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Instagram link'}),
            'qr': forms.ClearableFileInput(attrs={'class': f'{INPUT_CLASSES} bg-blue-500 text-white'}),
        }

    def clean_image(self):
        image = self.cleaned_data.get('image')

        if not image:
            raise forms.ValidationError("Please select an image.")
        
        return image
    
    def clean_qr(self):
        qr = self.cleaned_data.get('qr')

        if not qr:
            raise forms.ValidationError("Please select a QR image.")
        
        return qr
    
    


class EditItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = ('name', 'location', 'description', 'price', 'image', 'phone_number', 'email', 'is_available', 'is_negotiable', 'facebook', 'instagram', 'qr')

        widgets = {
            'name': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter item name'}),
            'location': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter location'}),
            'description': forms.Textarea(attrs={'class': f'{INPUT_CLASSES} resize-none', 'placeholder': 'Enter post description'}),  
            'price': forms.NumberInput(attrs={'class': f'{INPUT_CLASSES} text-green-500', 'placeholder': 'Enter Price per Day'}),
            'image': forms.ClearableFileInput(attrs={'class': f'{INPUT_CLASSES} bg-blue-500 text-white'}),
            'phone_number': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter phone number'}),
            'email': forms.EmailInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter email'}),
            'is_available': forms.CheckboxInput(attrs={'class': CHECKBOX_CLASSES}),
            'is_negotiable': forms.CheckboxInput(attrs={'class': CHECKBOX_CLASSES}),
            'facebook': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Facebook link'}),
            'instagram': forms.TextInput(attrs={'class': INPUT_CLASSES, 'placeholder': 'Enter Instagram link'}),
            'qr': forms.ClearableFileInput(attrs={'class': f'{INPUT_CLASSES} bg-blue-500 text-white'}),
        }

    def clean_image(self):
        image = self.cleaned_data.get('image')

        if not image:
            raise forms.ValidationError("Please select an image.")
        
        return image
    
    def clean_qr(self):
        qr = self.cleaned_data.get('qr')

        if not qr:
            raise forms.ValidationError("Please select a QR image.")
        
        return qr
    
    
    
