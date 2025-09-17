from django.views.generic.edit import FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy, reverse
from django.utils.translation import gettext_lazy as _, get_language
from django.core.exceptions import ValidationError
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import FileExtensionValidator
from django.http import JsonResponse
from django.views import View
from django.contrib import messages
from django.db import IntegrityError
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.utils.text import get_valid_filename
from django.http import HttpResponseForbidden, HttpResponseBadRequest
import os
import uuid
import io

from PIL import Image
import magic

from .forms import PostCreateForm, PostContentForm
from .models import Post, PostTranslation, PostImage, validate_image_size, MAX_POST_IMAGES

# Create your views here.

def _validate_image_size(file_obj):
    limit = 10 * 1024 * 1024  # 10MB
    if file_obj.size > limit:
        raise ValidationError("File size must not exceed 10MB.")


class PostCreateView(LoginRequiredMixin, FormView):
    form_class = PostCreateForm
    template_name = 'core/post_create.html'
    success_url = reverse_lazy('core:post_list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = _("Create New Post")

        content_form = PostContentForm()

        if hasattr(settings, 'TINYMCE_DEFAULT_CONFIG'):

            current_language = get_language() or 'en'
            tinymce_config = settings.TINYMCE_DEFAULT_CONFIG.copy()
            

            if current_language == 'fa':
                tinymce_config.update({
                    'language': 'fa',
                    'directionality': 'rtl',
                })
            elif current_language in ['ckb', 'ku']:
                tinymce_config.update({
                    'directionality': 'rtl',
                })
            else:
                tinymce_config.update({
                    'language': 'en_US',
                    'directionality': 'ltr',
                })
        
            content_form.fields['content'].widget.mce_attrs = tinymce_config
        
        context['content_form'] = content_form
        
        context['tinymce_config'] = getattr(settings, 'TINYMCE_DEFAULT_CONFIG', {})
        context['current_language'] = get_language() or 'en'
        
        return context

    def form_valid(self, form):
        post = form.save()
        image_files = self.request.FILES.getlist('createinputfile')
        
        if len(image_files) > MAX_POST_IMAGES:
            messages.error(self.request, _('You cannot upload more than {} images.').format(MAX_POST_IMAGES))
            form.add_error(None, _('Maximum {} images allowed.').format(MAX_POST_IMAGES))
            return self.form_invalid(form)

        file_validator = FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp'])
        for image_file in image_files:
            try:
                file_validator(image_file)
                validate_image_size(image_file)
            except ValidationError as e:
                messages.error(self.request, str(e))
                form.add_error(None, e)
                return self.form_invalid(form)
            
            post_image = PostImage(post=post, image=image_file)
            post_image.save()
        
        messages.success(self.request, _('Post created successfully with images.'))
        return super().form_valid(form)


@method_decorator(csrf_exempt, name='dispatch')
class PostAjaxView(View):
    def post(self, request):
        action = request.POST.get('action')

        # Helper function to get messages
        def get_messages_list():
            storage = messages.get_messages(request)
            return [{'level': message.level, 'message': str(message), 'tags': message.tags} for message in storage]

        if action == 'save_base':
            form = PostCreateForm(request.POST, request.FILES, user=request.user)
            try:
                if form.is_valid():
                    post = form.save()
                    image_files = request.FILES.getlist('createinputfile')
                    if len(image_files) > MAX_POST_IMAGES:
                        messages.error(request, _('You cannot upload more than {} images.').format(MAX_POST_IMAGES), extra_tags='error priority-2')
                        return JsonResponse({
                            'success': False,
                            'errors': {'non_field_errors': [_('Maximum {} images allowed.').format(MAX_POST_IMAGES)]},
                            'messages': get_messages_list()
                        })

                    file_validator = FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp'])
                    for image_file in image_files:
                        try:
                            file_validator(image_file)
                            validate_image_size(image_file)
                        except ValidationError as e:
                            messages.error(request, str(e), extra_tags='error priority-2')
                            return JsonResponse({
                                'success': False,
                                'errors': {'non_field_errors': [str(e)]},
                                'messages': get_messages_list()
                            })
                        post_image = PostImage(post=post, image=image_file)
                        post_image.save()
                    messages.success(request, _('Post base saved successfully. Proceed to content editing.'), extra_tags='success priority-0')
                    current_count = post.images.count()
                    return JsonResponse({
                        'success': True,
                        'post_id': post.id,
                        'current_count': current_count,
                        'messages': get_messages_list()
                    })
                else:
                    # Process form errors into user-friendly messages
                    for field, errors in form.errors.items():
                        for error in errors:
                            if field == 'slug' and 'unique' in error.lower():
                                messages.error(request, _('The slug "{}" is already taken. Please choose a different one.').format(form.data.get('slug', '')), extra_tags='error priority-2')
                            elif field == 'datetime_published' and 'invalid' in error.lower():
                                messages.error(request, _('The publish date is invalid. It must be a future date in YYYY-MM-DD HH:MM format.'), extra_tags='error priority-2')
                            elif field == '__all__':
                                messages.error(request, error, extra_tags='error priority-2')
                            else:
                                field_label = form.fields[field].label or field.capitalize()
                                messages.error(request, _('{field} error: {error}').format(field=field_label, error=error), extra_tags='error priority-2')
                    return JsonResponse({
                        'success': False,
                        'errors': form.errors,
                        'messages': get_messages_list()
                    })
            except IntegrityError as e:
                if 'unique_together' in str(e).lower():
                    messages.error(request, _('The slug "{}" is already taken. Please choose a different one.').format(form.data.get('slug', '')), extra_tags='error priority-2')
                else:
                    messages.error(request, _('An unexpected error occurred while saving the post.'), extra_tags='error priority-2')
                return JsonResponse({
                    'success': False,
                    'errors': {'non_field_errors': [str(e)]},
                    'messages': get_messages_list()
                })

        elif action == 'save_content':
            post_id = request.POST.get('post_id')
            try:
                post = Post.objects.get(id=post_id, author=request.user)
                language = get_language() or 'en'
                try:
                    translation = PostTranslation.objects.get(post=post, language=language)
                    form = PostContentForm(request.POST, instance=translation)
                except PostTranslation.DoesNotExist:
                    form = PostContentForm(request.POST, post=post, language=language)
                if form.is_valid():
                    form.save()
                    messages.success(request, _('Post content saved successfully.'), extra_tags='success priority-0')
                    return JsonResponse({
                        'success': True,
                        'redirect_url': reverse('core:post_detail', args=[post.id]),
                        'messages': get_messages_list()
                    })
                else:
                    for field, errors in form.errors.items():
                        for error in errors:
                            field_label = form.fields[field].label or field.capitalize()
                            messages.error(request, _('{field} error: {error}').format(field=field_label, error=error), extra_tags='error priority-2')
                    return JsonResponse({
                        'success': False,
                        'errors': form.errors,
                        'messages': get_messages_list()
                    })
            except Post.DoesNotExist:
                messages.error(request, _('Post not found.'), extra_tags='error priority-2')
                return JsonResponse({
                    'success': False,
                    'errors': [_('Post not found')],
                    'messages': get_messages_list()
                })

        elif action == 'add_image':
            post_id = request.POST.get('post_id')
            try:
                post = Post.objects.get(id=post_id, author=request.user)
                image_files = request.FILES.getlist('createinputfile')
                current_count = post.images.count()
                if current_count + len(image_files) > MAX_POST_IMAGES:
                    messages.error(request, _('You can upload at most {} more images.').format(MAX_POST_IMAGES - current_count), extra_tags='error priority-2')
                    return JsonResponse({
                        'success': False,
                        'errors': [_('Maximum {} images allowed.').format(MAX_POST_IMAGES)],
                        'messages': get_messages_list()
                    })

                file_validator = FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'webp'])
                for image_file in image_files:
                    try:
                        file_validator(image_file)
                        validate_image_size(image_file)
                    except ValidationError as e:
                        messages.error(request, str(e), extra_tags='error priority-2')
                        return JsonResponse({
                            'success': False,
                            'errors': [str(e)],
                            'messages': get_messages_list()
                        })
                    post_image = PostImage(post=post, image=image_file)
                    post_image.save()
                messages.success(request, _('Images added successfully.'), extra_tags='success priority-0')
                new_count = post.images.count()
                return JsonResponse({
                    'success': True,
                    'current_count': new_count,
                    'messages': get_messages_list()
                })
            except Post.DoesNotExist:
                messages.error(request, _('Post not found.'), extra_tags='error priority-2')
                return JsonResponse({
                    'success': False,
                    'errors': [_('Post not found')],
                    'messages': get_messages_list()
                })

        messages.error(request, _('Invalid action.'), extra_tags='error priority-2')
        return JsonResponse({
            'success': False,
            'errors': [_('Invalid action')],
            'messages': get_messages_list()
        })


@method_decorator(csrf_exempt, name="dispatch")
class TinyMCEUploadView(View):
    """
    Handles uploads for TinyMCE: images (with compression), videos, and audio (without processing).
    Returns JSON {"location": "<url>"} on success.
    Validates authentication, file type, extension, size, and real MIME type for security.
    Processing is minimal for speed: only images are compressed; media files are saved as-is.
    Note: For production, serve media from a separate subdomain/CDN to mitigate XSS risks (e.g., via Django's storage backends like S3).
    Ensure server-side CSP is configured to restrict media sources.
    """

    def post(self, request, *args, **kwargs):
        # Require authentication for security
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Authentication required to upload files.")

        uploaded = request.FILES.get("file")
        if not uploaded:
            return HttpResponseBadRequest("No file uploaded.")

        name = uploaded.name

        # Detect real MIME type using python-magic for security (prevents disguised malicious files)
        mime = magic.Magic(mime=True)
        uploaded.seek(0)  # Reset file pointer
        buffer = uploaded.read(1024)  # Read initial bytes for MIME detection
        uploaded.seek(0)  # Reset again
        content_type = mime.from_buffer(buffer)

        # Define allowed types, extensions, and size limits for security and efficiency
        if content_type.startswith('image/'):
            allowed_ext = ['jpg', 'jpeg', 'png', 'webp']
            allowed_mimes = ['image/jpeg', 'image/png', 'image/webp']
            max_size = 10 * 1024 * 1024  # 10MB for images
        elif content_type.startswith('video/'):
            allowed_ext = ['mp4', 'webm', 'ogg']
            allowed_mimes = ['video/mp4', 'video/webm', 'video/ogg']
            max_size = 100 * 1024 * 1024  # 100MB for videos
        elif content_type.startswith('audio/'):
            allowed_ext = ['mp3', 'wav', 'ogg']
            allowed_mimes = ['audio/mpeg', 'audio/wav', 'audio/ogg']
            max_size = 20 * 1024 * 1024  # 20MB for audio
        else:
            return JsonResponse({"error": "Unsupported file type. Only images, videos, and audio are allowed."}, status=400)

        # Validate extension for additional security
        ext = name.lower().rsplit('.', 1)[-1] if '.' in name else ''
        if ext not in allowed_ext:
            return JsonResponse({"error": f"Invalid file extension. Allowed: {', '.join(allowed_ext)}"}, status=400)

        # Validate detected MIME against allowed list
        if content_type not in allowed_mimes:
            return JsonResponse({"error": f"Invalid file content type. Detected: {content_type}. Allowed: {', '.join(allowed_mimes)}"}, status=400)

        # Validate size for security and performance
        if uploaded.size > max_size:
            return JsonResponse({"error": f"File size exceeds {max_size // (1024 * 1024)}MB limit for this type."}, status=400)

        # Sanitize filename for security
        valid_name = get_valid_filename(name)
        name_root, ext = os.path.splitext(valid_name)
        unique_name = f"{name_root}-{uuid.uuid4().hex}{ext}"
        save_path = os.path.join("tinymce_uploads", unique_name)

        try:
            if content_type.startswith('image/'):
                # Process image: compress to WEBP for optimization (fast with PIL)
                # This also implicitly validates it's a real image (PIL will raise if not)
                img = Image.open(uploaded)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                img.thumbnail((1600, 1600))  # Bound size for efficiency
                output = io.BytesIO()
                img.save(output, format='WEBP', quality=85)
                content = ContentFile(output.getvalue())
                final_name = os.path.splitext(unique_name)[0] + '.webp'
                final_path = default_storage.save(os.path.join("tinymce_uploads", final_name), content)
            else:
                # For video/audio: save as-is (fastest, no processing)
                # Additional validation could be added (e.g., ffprobe for videos), but skipped for speed
                final_path = default_storage.save(save_path, uploaded)
        except Exception as e:
            # Fail securely if processing errors (e.g., invalid file masquerading as image)
            return JsonResponse({"error": "File processing failed. Ensure the file is valid and not corrupted."}, status=400)

        file_url = settings.MEDIA_URL + final_path
        return JsonResponse({"location": file_url})
