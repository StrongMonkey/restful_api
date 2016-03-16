from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden
from oauth2client import client
from models import User, Request, Proposal, MealDate
from django.db.models import Q
import logging
import httplib2
import json
from datetime import datetime
from ratelimit.decorators import ratelimit

logger = logging.getLogger('meetAndEat.views')
# Create your views here.


def api_list(request):
    return render(request, 'api_list.html')


def login(request):
    '''
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
    '''
    return render(request, 'login.html')


def auth(request):
    flow = client.flow_from_clientsecrets(
        'restful_api/client_secret.json',
        scope={
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        },
        redirect_uri='http://localhost:8000/restful_api/index'
    )
    auth_uri = flow.step1_get_authorize_url()
    return redirect(auth_uri)


def index(request):
    if request.method == 'GET':
        code = request.GET.get('code')
        print code
        context = {
            'code': code,
        }
        return render(request, 'hello.html', context)


def complete(request):
    auth_code = request.GET.get('code')
    try:
        flow = client.flow_from_clientsecrets(
            'restful_api/client_secret.json',
            scope='',
            redirect_uri='http://localhost:8000/restful_api/index'
        )
    except client.FlowExchangeError:
        return HttpResponseForbidden('Failed to upgrade the authorization code.')
    if auth_code is not None:
        credentials = flow.step2_exchange(auth_code)
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/plus/v1/people/me?access_token=%s' % access_token)
        h = httplib2.Http()
        data = h.request(url, 'GET')
        profile_data = json.loads(data[1])
        picture = profile_data.get('image').get('url')
        email = profile_data.get('emails')[0].get('value')
        user = User.objects.filter(email=email).first()
        username = email.split('@')[0]
        if not user:
            user = User(username=username, picture=picture, email=email)
            user.save()
            token = user.generate_auth_token()
            return JsonResponse(
                {
                    'status': 'user created successfully!',
                    'token': token.decode('ascii'),
                    'object':
                        {
                            'username': user.username,
                            'picture': str(user.picture),
                            'email': user.email
                        }
                }
            )
        else:
            token = user.generate_auth_token()
            return JsonResponse(
                {
                    'status': 'user already exist with the associated email address!',
                    'token': token.decode('ascii')
                }
            )


def logout(request):
    token = request.GET.get('token', '')
    user_id_login = User.invalidate(token)
    if user_id_login:
        logger.info('user ' + user_id_login + ' is logged out!')
        return HttpResponse('user ' + user_id_login + ' is logged out!')
    else:
        return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def users(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        if request.method == 'GET':
            token = request.GET.get('token')
            print token
            user_id = User.verify_auth_token(token)
            if user_id:
                all_users = User.objects.all()
                data = []
                for user in all_users:
                    item = {
                                'username': user.username,
                                'picture': str(user.picture),
                                'email': user.email
                            }
                    data.append(item)
                return JsonResponse(
                    {
                        'users': data
                    }
                )
            else:
                return HttpResponseForbidden('invalid token')
        elif request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = User.objects.filter(username=username)
            if not user:
                user = User(username=username, password=password)
                user.save()
                logger.info('username ' + username + ' created')
                return JsonResponse(
                        {
                            'status': 'user created successfully',
                            'object':
                                {
                                    'username': user.username,
                                    'picture': str(user.picture),
                                    'email': user.email
                                }
                        }
                    )
            else:
                return JsonResponse(
                        {
                            'status': 'user already exist!',
                            'object':
                                {
                                    'username': user.username,
                                    'picture': str(user.picture),
                                    'email': user.email
                                }
                        }
                    )
        elif request.method == 'PUT':
            raw_data = request.body
            data = raw_data.json()
            token = data['token']
            profile_data = data['profile']
            user_id_login = User.verify_auth_token(token)
            if user_id_login:
                user = User.objects.filter(id=user_id_login).first()
                if user:
                    user.username = profile_data['username']
                    user.picture = profile_data['picture']
                    user.save()
                    # logger.info('user ' + user_id_login + ' profile updated successfully!')
                    return JsonResponse(
                        {
                            'status': 'update successfully',
                            'object':
                                {
                                    'username': user.username,
                                    'picture': str(user.picture),
                                    'email': user.email
                                }
                        }
                    )
                else:
                    return JsonResponse({'status': 'update operation failed'})
            else:
                return HttpResponseForbidden('invalid token')
        elif request.method == 'DELETE':
            raw_data = request.body
            data = raw_data.json()
            token = data['token']
            user_id = User.verify_auth_token(token)
            if user_id:
                user = User.objects.filter(id=user_id).first()
                user.delete()
            else:
                return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def profile(request, user_id):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = request.GET.get('token')
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            user = User.objects.filter(id=user_id).first()
            return JsonResponse(
                {
                    'object':
                        {
                            'username': user.username,
                            'picture': str(user.picture),
                            'email': user.email
                        }

                }
            )
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def requests(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            if request.method == 'GET':
                all_requests = Request.objects.all()
                data = []
                for request_instance in all_requests:
                    item = {
                                'id': request_instance.id,
                                'user_id': request_instance.user_id.id,
                                'meal_type': request_instance.meal_type,
                                'location_string': request_instance.location_string,
                                'latitude': request_instance.latitude,
                                'longitude': request_instance.longitude,
                                'meal_time': str(request_instance.meal_time)
                            }
                    data.append(item)
                return JsonResponse(
                    {
                        'objects': data
                    }
                )
            elif request.method == 'POST':
                user = User.objects.get(id=user_id_login)
                if user:
                    meal_type = request.POST.get('meal_type')
                    location_string = request.POST.get('location_string')
                    latitude = request.POST.get('latitude')
                    longitude = request.POST.get('longitude')
                    meal_time = datetime.strptime(request.POST.get('meal_time'), "%Y %b %d %H:%M")
                    request_instance = Request(
                                                user_id=user,
                                                meal_type=meal_type,
                                                location_string=location_string,
                                                latitude=latitude,
                                                longitude=longitude,
                                                meal_time=meal_time
                                                )
                    request_instance.save()
                    return JsonResponse(
                        {
                            'status': 'instance create successfully',
                            'object':
                                {
                                    'id': request_instance.id,
                                    'user_id': request_instance.user_id.id,
                                    'meal_type': request_instance.meal_type,
                                    'location_string': request_instance.location_string,
                                    'latitude': request_instance.latitude,
                                    'longitude': request_instance.longitude,
                                    'meal_time': str(request_instance.meal_time)
                                }
                        }
                    )
                else:
                    return HttpResponseForbidden('user not exist!')
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def detail_request(request, request_id):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            request_instance = Request.objects.filter(id=request_id).first()
            if user_id_login == request_instance.user_id.id:
                if request.method == 'GET':
                    return JsonResponse(
                        {
                            'status': '200 ok',
                            'object':
                                {
                                    'id': request_instance.id,
                                    'user_id': request_instance.user_id.id,
                                    'meal_type': request_instance.meal_type,
                                    'location_string': request_instance.location_string,
                                    'latitude': request_instance.latitude,
                                    'longitude': request_instance.longitude,
                                    'meal_time': str(request_instance.meal_time)
                                }
                        }
                    )
                elif request.method == 'PUT':
                    data = json.loads(request.body)
                    meal_type = data.get('meal_type')
                    location_string = data.get('location')
                    latitude = data.get('latitude')
                    longitude = data.get('longitude')
                    meal_time = data.get('meal_time')
                    request.update(meal_type=meal_type, location_string=location_string,
                                   latitude=latitude, longitude=longitude, meal_time=meal_time)
                    return JsonResponse(
                        {
                            'status': 'instance updated successfully!',
                            'object':
                                {
                                    'id': request_instance.id,
                                    'user_id': request_instance.user_id.id,
                                    'meal_type': request_instance.meal_type,
                                    'location_string': request_instance.location_string,
                                    'latitude': request_instance.latitude,
                                    'longitude': request_instance.longitude,
                                    'meal_time': str(request_instance.meal_time)
                                }
                        }
                    )
                elif request.method == 'DELETE':
                    request_instance = Request.objects.filter(request_id=request_id).first()
                    request_instance.delete()
                    return JsonResponse({'status': 'instance deleted successfully'})
            else:
                return HttpResponseForbidden('not original request maker')
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def proposals(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            if request.method == 'GET':
                all_request = Request.objects.filter(user_id=user_id_login)
                request_id = []
                for r in all_request:
                    request_id.append(r.id)
                all_proposal = Proposal.objects.filter(request_id in request_id)
                data = []
                for proposal in all_proposal:
                    item = {
                                'id': proposal.id,
                                'user_proposed_to': proposal.user_proposed_to,
                                'user-proposed_from': proposal.user_proposed_from,
                                'request_id': proposal.request_id.id,
                                'filled': proposal.filled
                            }
                    data.append(item)
                return JsonResponse(
                    {
                        'objects': data
                    }
                )
            elif request.method == 'POST':
                request_id = request.POST.get('request_id')
                user_from = Request.objects.filter(id=request_id).first().user_id
                user_to = user_id_login
                if user_from == user_to:
                    return HttpResponseForbidden('the two users are same')
                else:
                    proposal = Proposal(user_proposed_to=user_to, user_proposed_from=user_from, request_id=request_id)
                    proposal.save()
                    return JsonResponse(
                        {
                            'status': 'proposal created successfully',
                            'object':
                                {
                                    'id': proposal.id,
                                    'user_proposed_to': proposal.user_proposed_to,
                                    'user-proposed_from': proposal.user_proposed_from,
                                    'request_id': proposal.request_id.id,
                                    'filled': proposal.filled
                                }
                        }
                    )
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def detail_proposal(request, proposal_id):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        proposal = Proposal.objects.filter(id=proposal_id).first()
        if user_id_login:
            if proposal.user_proposed_from == user_id_login or proposal.user_proposed_to == user_id_login:
                if request.method == 'GET':
                    return JsonResponse(
                        {
                            'object':
                                {
                                    'id': proposal.id,
                                    'user_proposed_to': proposal.user_proposed_to,
                                    'user-proposed_from': proposal.user_proposed_from,
                                    'request_id': proposal.request_id.id,
                                    'filled': proposal.filled
                                }
                        }
                    )
                elif request.method == 'PUT':
                    data = json.load(request.body)
                    user_to = data['user_to']
                    user_from = data['user_form']
                    request_id = data['request_id']
                    proposal = Proposal.objects.filter(id=proposal_id).first()
                    proposal.update(user_proposed_to=user_to, user_proposed_from=user_from, request_id=request_id)
                    return JsonResponse(
                        {
                            'status': 'update proposal successfully',
                            'object':
                                {
                                    'id': proposal.id,
                                    'user_proposed_to': proposal.user_proposed_to,
                                    'user-proposed_from': proposal.user_proposed_from,
                                    'request_id': proposal.request_id.id,
                                    'filled': proposal.filled
                                }
                        }
                    )
                elif request.method == 'DELETE':
                    proposal.delete()
                    return JsonResponse({'status': 'delete successfully'})
            else:
                return HttpResponseForbidden('the current user has no access to the proposal')
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def dates(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            if request.method == 'GET':
                meal_dates = MealDate.objects.filter(Q(user_1=user_id_login) | Q(user_2=user_id_login))
                data = []
                for meal_date in meal_dates:
                    item = {
                        'id': meal_date.id,
                        'user_1': meal_date.user_1,
                        'user_2': meal_date.user_2,
                        'restaurant_name': meal_date.restaurant_name,
                        'restaurant_address': meal_date.restaurant_address,
                        'restaurant_picture': meal_date.restaurant_picture,
                        'meal_time': meal_date.meal_time
                    }
                    data.append(item)
                return JsonResponse(
                    {
                        'objects': data
                    }
                )
            elif request.method == 'POST':
                is_agreed = request.POST.get('agreed')
                proposals_id = request.POST.get('proposal_id')
                if is_agreed:
                    proposals_instance = Proposal.objects.get(id=proposals_id)
                    request_instance = Request.objects.get(id=proposals_instance.request_id.id)
                    meal_date = MealDate(
                            user_1=proposals_instance.user_proposed_to,
                            user_2=proposals_instance.user_proposed_from,
                            meal_time=request_instance.meal_time
                    )
                    meal_date.save()
                    return JsonResponse(
                        {
                            'status': 'instance created successfully',
                            'object':
                                {
                                    'id': meal_date.id,
                                    'user_1': meal_date.user_1,
                                    'user_2': meal_date.user_2,
                                    'restaurant_name': meal_date.restaurant_name,
                                    'restaurant_address': meal_date.restaurant_address,
                                    'restaurant_picture': meal_date.restaurant_picture,
                                    'meal_time': meal_date.meal_time
                                }
                        }
                    )
                else:
                    proposals_instance = Proposal.objects.get(id=proposals_id)
                    proposals_instance.delete()
                    return JsonResponse({'status': 'instance deleted successfully'})
        else:
            return HttpResponseForbidden('invalid token')


@ratelimit(key='ip', rate='5/m', method=['POST', 'PUT', 'PATCH', 'DELETE'])
def detail_dates(request, date_id):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse(
            {
                'status': 'you hit the rate limit!'
            }
        )
    else:
        token = get_token(request)
        user_id_login = User.verify_auth_token(token)
        if user_id_login:
            meal_date = MealDate.objects.get(id=date_id)
            if meal_date.user_1 == user_id_login or meal_date.user_2 == user_id_login:
                if request.method == 'GET':
                    return JsonResponse(
                        {
                            'object':
                                {
                                    'id': meal_date.id,
                                    'user_1': meal_date.user_1,
                                    'user_2': meal_date.user_2,
                                    'restaurant_name': meal_date.restaurant_name,
                                    'restaurant_address': meal_date.restaurant_address,
                                    'restaurant_picture': meal_date.restaurant_picture,
                                    'meal_time': meal_date.meal_time
                                }
                        }
                    )
                elif request.method == 'PUT':
                    data = request.body.json()
                    restaurant_name = data['restaurant_name']
                    restaurant_address = data['restaurant_address']
                    restaurant_picture = data['restaurant_picture']
                    meal_time = data['meal_time']
                    meal_date.update(
                                restaurant_name=restaurant_name,
                                restaurant_address=restaurant_address,
                                restaurant_picture=restaurant_picture,
                                meal_time=meal_time
                    )
                    return JsonResponse(
                        {
                            'status': 'update successfully',
                            'object':
                                {
                                    'id': meal_date.id,
                                    'user_1': meal_date.user_1,
                                    'user_2': meal_date.user_2,
                                    'restaurant_name': meal_date.restaurant_name,
                                    'restaurant_address': meal_date.restaurant_address,
                                    'restaurant_picture': meal_date.restaurant_picture,
                                    'meal_time': meal_date.meal_time
                                }
                        }
                    )
                elif request.method == 'DELETE':
                    meal_date.delete()
                    return JsonResponse({'status': 'delete successfully'})
            else:
                return HttpResponseForbidden('the current user has no access to the date info')
        else:
            return HttpResponseForbidden('invalid token')


def get_token(request):
    if request.method == 'GET':
        return request.GET.get('token')
    elif request.method == 'POST':
        return request.POST.get('token')
    elif request.method == 'PUT' or request.method == 'DELETE':
        data = json.loads(request.body)
        return data['token']


















