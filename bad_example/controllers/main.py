from odoo import http
from odoo.exceptions import AccessError
from odoo.http import request
from odoo.service import security
from odoo.addons.web.controllers.utils import ensure_db, is_user_internal

class Home(http.Controller):
    # Sudo
    @http.route('/bad/example/sudo', type='http', auth="none") # auth="user"
    def sudo(self, **kw):
        users = request.env['res.users'].sudo().search([]).read(['id', 'name', 'login'])
        return request.make_json_response({
            'data': users
        })

    # SQL Injection
    @http.route('/bad/example/sql_injection', type='http', auth="none")
    def sql_injection(self, name=None, **kw):
        cr = request.cr
        # "Test'; SELECT login, password FROM res_users;--"
        query = f"""SELECT * FROM res_partner
                        WHERE name ILIKE '%{name}%'""" # %(name)s
        cr.execute(query) # {'name': f"%{name}%",}
        partners = cr.fetchall()
        # partners = request.env['res.partner'].sudo().search([('name', 'ilike', name)]).read(['id', 'name'])
        return request.make_json_response({
            'data': partners,
            'query': name
        })

    # XSS Attack
    @http.route('/bad/example/xss', type='http', auth="none")
    def xss(self, s_action=None, **kw):
        ensure_db()
        if not request.session.uid:
            return request.redirect('/web/login', 303)
        if kw.get('redirect'):
            return request.redirect(kw.get('redirect'), 303)
        if not security.check_session(request.session, request.env):
            raise http.SessionExpiredException("Session expired")
        if not is_user_internal(request.session.uid):
            return request.redirect('/web/login_successful', 303)

        request.session.touch()

        request.update_env(user=request.session.uid)
        try:
            context = request.env['ir.http'].webclient_rendering_context()
            context['s_action'] = s_action
            response = request.render('bad_example.webclient_bootstrap', qcontext=context)
            response.headers['X-Frame-Options'] = 'DENY'
            return response
        except AccessError:
            return request.redirect('/web/login?error=access')
