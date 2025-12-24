import unittest
import json
import tempfile
import os
from app import app, db, User, Department, Call, CallStatus

class APITestCase(unittest.TestCase):

    def setUp(self): #изоляция
        self.db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.db')
        self.test_app = app
        self.test_app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self.temp_db_path}'
        self.test_app.config['TESTING'] = True
        self.test_app.config['WTF_CSRF_ENABLED'] = False

        self.app = self.test_app.test_client()
        with self.test_app.app_context():
            db.session.remove()
            db.drop_all()
            db.create_all()
            dept_medical = Department(name='medical')
            dept_fire = Department(name='fire')
            dept_police = Department(name='police')
            admin_user = User(username='test_admin', role='admin')
            admin_user.set_password('password')
            dispatcher_user = User(username='test_dispatcher', role='dispatcher')
            dispatcher_user.set_password('password')
            medical_user = User(username='test_medical', role='medical')
            medical_user.set_password('password')
            fire_user = User(username='test_fire', role='fire')
            fire_user.set_password('password')
            police_user = User(username='test_police', role='police')
            police_user.set_password('password')
            db.session.add_all([dept_medical, dept_fire, dept_police,
                                admin_user, dispatcher_user, medical_user, fire_user, police_user])
            db.session.commit()
            self.admin_user_id = admin_user.id
            self.dispatcher_user_id = dispatcher_user.id
            self.medical_user_id = medical_user.id
            self.fire_user_id = fire_user.id
            self.police_user_id = police_user.id

            self.dept_medical_id = dept_medical.id
            self.dept_fire_id = dept_fire.id
            self.dept_police_id = dept_police.id

    def tearDown(self): #терминейт сессии после теста 
        with self.test_app.app_context():
            db.session.remove()
            db.drop_all()
        os.close(self.db_fd)
        os.unlink(self.temp_db_path)

    def login(self, username, password):
        return self.app.post('/auth/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/auth/logout', follow_redirects=True)

    def test_01_api_login_dispatcher_create_call(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 01',
            'description': 'Test 01',
            'departments': [self.dept_medical_id, self.dept_police_id]
        }
        rv = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv.status_code, 201)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertIn('id', response_data)
        self.assertIn('message', response_data)
        self.assertIn('departments', response_data)
        self.assertIn('statuses_by_department', response_data)

        created_call_id = response_data['id']
        rv_get = self.app.get(f'/api/calls/{created_call_id}')
        self.assertEqual(rv_get.status_code, 200)
        get_data = json.loads(rv_get.get_data(as_text=True))
        self.assertEqual(get_data['id'], created_call_id)
        self.assertEqual(get_data['location'], 'Test 01')
        self.logout()

    def test_02_api_get_calls_dispatcher(self): 
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 02',
            'description': 'Test 02',
            'departments': [self.dept_fire_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        created_call_id = json.loads(rv_create.get_data(as_text=True))['id']
        rv = self.app.get('/api/calls')
        self.assertEqual(rv.status_code, 200)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertIsInstance(response_data, list)
        found = any(call['id'] == created_call_id for call in response_data)
        self.assertTrue(found, "Created call not found in dispatcher's list")
        self.logout()

    def test_03_api_get_call_detail_dispatcher(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 03',
            'description': 'Test 03',
            'departments': [self.dept_police_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        created_call_id = json.loads(rv_create.get_data(as_text=True))['id']
        rv = self.app.get(f'/api/calls/{created_call_id}')
        self.assertEqual(rv.status_code, 200)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertEqual(response_data['id'], created_call_id)
        self.assertEqual(response_data['location'], 'Test 03')
        self.assertIn('statuses_by_department', response_data)
        self.logout()

    def test_04_api_update_call_dispatcher(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 04',
            'description': 'Test 04',
            'departments': [self.dept_medical_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        created_call_id = json.loads(rv_create.get_data(as_text=True))['id']
        update_data = {
            'location': 'Updated 04',
            'description': 'Updated 04'
        }

        rv = self.app.put(f'/api/calls/{created_call_id}', data=json.dumps(update_data), content_type='application/json')
        self.assertEqual(rv.status_code, 200)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertIn('message', response_data)

        rv_check = self.app.get(f'/api/calls/{created_call_id}')
        check_data = json.loads(rv_check.get_data(as_text=True))
        self.assertEqual(check_data['location'], 'Updated 04')
        self.assertEqual(check_data['description'], 'Updated 04')
        self.logout()

    def test_05_api_update_call_status_medical(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 05',
            'description': 'Test 05',
            'departments': [self.dept_medical_id, self.dept_police_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        created_call_id = json.loads(rv_create.get_data(as_text=True))['id']
        self.logout()
        rv = self.login('test_medical', 'password')
        self.assertIn(rv.status_code, [200, 302])
        status_data = {
            'status': 'on_way'
        }
        rv = self.app.put(f'/api/calls/{created_call_id}/status', data=json.dumps(status_data), content_type='application/json')
        self.assertEqual(rv.status_code, 200)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertIn('message', response_data)
        self.assertEqual(response_data['status'], 'on_way')
        self.assertEqual(response_data['department'], 'medical')
        rv_check = self.app.get(f'/api/calls/{created_call_id}')
        check_data = json.loads(rv_check.get_data(as_text=True))
        self.assertEqual(check_data['statuses_by_department']['medical'], 'on_way')
        self.assertEqual(check_data['statuses_by_department']['police'], 'dispatched')
        self.logout()

    def test_06_api_delete_call_admin(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 06',
            'description': 'Test 06',
            'departments': [self.dept_fire_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        created_call_id = json.loads(rv_create.get_data(as_text=True))['id']
        self.logout()
        rv = self.login('test_admin', 'password')
        self.assertIn(rv.status_code, [200, 302])
        rv = self.app.delete(f'/api/calls/{created_call_id}')
        self.assertEqual(rv.status_code, 200)
        response_data = json.loads(rv.get_data(as_text=True))
        self.assertIn('message', response_data)
        rv_check = self.app.get(f'/api/calls/{created_call_id}')
        self.assertEqual(rv_check.status_code, 404)
        self.logout()

    def test_07_api_permissions(self):
        rv = self.login('test_dispatcher', 'password')
        self.assertIn(rv.status_code, [200, 302])
        call_data = {
            'location': 'Test 07',
            'description': 'Test 07',
            'departments': [self.dept_fire_id]
        }
        rv_create = self.app.post('/api/calls', data=json.dumps(call_data), content_type='application/json')
        self.assertEqual(rv_create.status_code, 201)
        call_id_perm = json.loads(rv_create.get_data(as_text=True))['id']
        self.logout()
        rv = self.login('test_police', 'password')
        self.assertIn(rv.status_code, [200, 302])
        rv = self.app.get(f'/api/calls/{call_id_perm}')
        self.assertEqual(rv.status_code, 403)
        status_data = {'status': 'closed'}
        rv = self.app.put(f'/api/calls/{call_id_perm}/status', data=json.dumps(status_data), content_type='application/json')
        self.assertEqual(rv.status_code, 403)
        new_call_data = {
            'location': 'Unauthorized Call',
            'description': 'Should not be created',
            'departments': [self.dept_police_id]
        }
        rv = self.app.post('/api/calls', data=json.dumps(new_call_data), content_type='application/json')
        self.assertEqual(rv.status_code, 403)
        self.logout()
        rv = self.app.get('/api/calls')
        self.assertEqual(rv.status_code, 302) 
        rv = self.login('test_police', 'password')
        self.assertIn(rv.status_code, [200, 302])
        rv = self.app.delete(f'/api/calls/{call_id_perm}')
        self.assertEqual(rv.status_code, 403)
        self.logout()


if __name__ == '__main__':
    unittest.main()