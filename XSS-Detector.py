# -*- coding: utf-8 -*-

from ast import List
from email import header
from burp import IBurpExtender, ITab, IProxyListener
#librerias necesarias para la interfaz del tab
from javax.swing import JButton, JPanel, JLabel, JTextField, BoxLayout, DefaultListModel, JList, JPanel, JScrollPane
from javax.swing.border import EmptyBorder
from java.awt import FlowLayout, Dimension
import threading
import urllib

class BurpExtender(IBurpExtender, ITab, IProxyListener):
#Vars
    VERSION = "1.0"
    reflect = "XSS-Detected-Challenge"
    endpoints = []
    domain = ""
    port = "443"
    protocol = "https"
    # Base header
    base_header = []
    
#IBurpExtender
    #Configuracion inicial de extension
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Detector")
        callbacks.issueAlert("La extension ha sido cargada exitosamente.")
        callbacks.registerProxyListener(self)
        callbacks.addSuiteTab(self)

#ITab
    # Titulo
    def getTabCaption(self):
        return "XSS Detector"

    # UI
    def getUiComponent(self):
        # Panel Principal
        main_panel = JPanel()
        main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

        # Sección 1: Info
        info_panel = JPanel()
        info_panel.setPreferredSize(Dimension(850, 100))
        info_panel.setLayout(FlowLayout(FlowLayout.CENTER, 0, 0))
        
        titleLabel = JLabel("<html><center><h1>XSS Detector</h1>Creado por: <em>Lorenzo Moriconi</em> (@vik-07)<br />Version: " + self.VERSION + "</center><br />")
        titleLabel.putClientProperty("html.disable", None)
        titleLabel.setBorder(EmptyBorder(0, 0, 0, 20))
        initialText = "<html><em>XSS Detector es una extension que nos permite detectar posibles XSS en diferentes endpoints que seran<br />detectados automaticamente a partir de navegar en el dominio dado o que puedes agregar manualmente.<br />Esta herramienta detecta los parametros de tipo URL y Body.</em><br />"
        htmlDescription = JLabel(initialText)
        htmlDescription.putClientProperty("html.disable", None)
        htmlDescription.setBorder(EmptyBorder(0, 20, 0, 0))

        info_panel.add(titleLabel)
        info_panel.add(htmlDescription)
        
        # Sección 2: Config + Output
        config_out_panel = JPanel()
        config_out_panel.setPreferredSize(Dimension(850, 500))
        config_out_panel.setLayout(BoxLayout(config_out_panel, BoxLayout.X_AXIS))

        # Sección 2.1: Config
        config_panel = JPanel()
        config_panel.setPreferredSize(Dimension(200, 400))
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(EmptyBorder(50, 50, 30, 50))

        l_dominio = JLabel("Dominio:")
        l_dominio.setBorder(EmptyBorder(0, 0, 4, 400))

        self.domain_field = JTextField(30)
        self.domain_field.addActionListener(lambda event: self.changeDomain(event))
        self.domain_field.setPreferredSize(Dimension(20, 25))

        l_port = JLabel("Puerto:")
        l_port.setBorder(EmptyBorder(12, 0, 4, 400))

        self.port_field = JTextField(5)
        self.port_field.setText(self.port)
        self.port_field.setPreferredSize(Dimension(5, 25))

        l_protocol = JLabel("Protocolo:")
        l_protocol.setBorder(EmptyBorder(12, 0, 4, 400))

        self.protocol_field = JTextField(5)
        self.protocol_field.setText(self.protocol)
        self.protocol_field.setPreferredSize(Dimension(5, 25))

        l_input = JLabel("Agregar endpoint:")
        l_input.setBorder(EmptyBorder(12, 0, 4, 400))

        self.input_field = JTextField(5)
        self.input_field.setText("POST /example/endpoint?p1=value&p2=value")
        self.input_field.addActionListener(lambda event: self.addEndpoint(event))
        self.input_field.setPreferredSize(Dimension(5, 25))

        l_endpoints = JLabel("Endpoints:")
        l_endpoints.setBorder(EmptyBorder(12, 0, 4, 400))

        self.list_endpoints = DefaultListModel()
        for endpoint in self.endpoints:
            self.list_endpoints.addElement(endpoint)
        self.l_endpoints = JList(self.list_endpoints)
        self.scroll_pane_endpoints = JScrollPane(self.l_endpoints)
        self.scroll_pane_endpoints.setPreferredSize(Dimension(30, 450))

        config_panel.add(l_dominio)
        config_panel.add(self.domain_field)
        config_panel.add(l_port)
        config_panel.add(self.port_field)
        config_panel.add(l_protocol)
        config_panel.add(self.protocol_field)
        config_panel.add(l_input)
        config_panel.add(self.input_field)
        config_panel.add(l_endpoints)
        config_panel.add(self.scroll_pane_endpoints)

        # Sección 2.2: Execute        
        execute_panel_output = JPanel()
        execute_panel_output.setPreferredSize(Dimension(650, 450))
        execute_panel_output.setAlignmentY(JPanel.CENTER_ALIGNMENT)
        execute_panel_output.setBorder(EmptyBorder(30, 0, 130, 0))

        scan_button = JButton("Iniciar XSS Detector")
        scan_button.setPreferredSize(Dimension(200, 30))
        scan_button.addActionListener(self.lightScan)

        l_endpoint_recon = JLabel("Informacion del scan:")
        l_endpoint_recon.setBorder(EmptyBorder(20, 0, 4, 500))

        self.list_endpoint_recon = DefaultListModel()
        for payload in self.endpoints:
            self.list_endpoint_recon.addElement(payload)
        self.l_endpoints_recon = JList(self.list_endpoint_recon)
        self.scroll_pane_endpoints_recon = JScrollPane(self.l_endpoints_recon)
        self.scroll_pane_endpoints_recon.setPreferredSize(Dimension(650, 450))
        
        execute_panel_output.add(scan_button)
        execute_panel_output.add(l_endpoint_recon)
        execute_panel_output.add(self.scroll_pane_endpoints_recon)

        config_out_panel.add(config_panel)
        config_out_panel.add(execute_panel_output)

        main_panel.add(info_panel)
        main_panel.add(config_out_panel)

        scrollPane = JScrollPane(main_panel)
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)

        return scrollPane

#IProxyListener
    def processProxyMessage(self, messageIsRequest, message):
        # Solo procesar Request
        if messageIsRequest:
            request = message.getMessageInfo().getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            headers = analyzedRequest.getHeaders()
            self.domain = self.domain_field.getText().replace(" ", "")
            # Filtro solo las peticiones del dominio solicitado
            if headers[1].split(" ")[1] == self.domain: # 'Host: example.com' -> 'example.com'
                their_params = analyzedRequest.getParameters()
                new_endpoint = headers[0].split(" ")[1].split('?')[0] # 'GET /endpoint/example?test=123 HTTP/2' -> '/endpoint/example'
                # Validar si ya se agrego el endpoint
                for e in self.endpoints:
                    if e.endpoint == new_endpoint:
                        return
                filter_params = self.validarParms(their_params)

                if len(filter_params) != 0:
                    h = headers[0].split(" ") # ['verb', 'endpoint', 'protocol']
                    header = Header(h[0], h[2], headers[2], headers[3:]) # Creo un objeto del tipo Header (verb, protocol, cookie, rest_of_headers)
                    endpoint = Endpoint(header, self.domain, new_endpoint, filter_params) # Creo un objeto del tipo Endoint (Header, domain, endpoint, Parameter)
                    self.endpoints.append(endpoint)
                    # Cargo los headers por defecto
                    if len(self.base_header) == 0:
                        self.base_header.append(h[2])
                        self.base_header.append(headers[2])
                        self.base_header.append(headers[3:])
                    # Actualizo el scroll pane
                    self.list_endpoints.addElement(new_endpoint)
                    self.l_endpoints.setModel(self.list_endpoints)
                    self.scroll_pane_endpoints.revalidate()
                    self.scroll_pane_endpoints.repaint()

#Funciones
    def validarParms(self, parameters):
        params = [] # Lista que contendra todos los objetos Parameter 
        for p in parameters:
            tipo = p.getType()
            # (Mejora futura) Implementar para los otros formatos
            if tipo == 0 or tipo == 1: # 0: param URL, 1: param Body los demas son cookie y otros formatos(JSON, XML, etc)
                param = Parameter(p)
                params.append(param)
        return params
    
    def lightScan(self, none): # Utilizo el parametro none para poder ejecutar el metodo sin problemas, ya que la funcion addActionListener pasa un parametro automaticamente
        self.list_endpoint_recon = DefaultListModel()
        if len(self.endpoints) != 0:
            self.list_endpoint_recon.addElement("-- INICIO DE ESCANEO --")
            self.l_endpoints_recon.setModel(self.list_endpoint_recon)
            self.scroll_pane_endpoints_recon.revalidate()
            self.scroll_pane_endpoints_recon.repaint()
            self.prepareFinalEndpoint()
        else:
            if self.domain == "":
                self.list_endpoint_recon.addElement("-(Error)  Aun no se cargo el dominio.")
            else:
                self.list_endpoint_recon.addElement("-(Error)  Aun no se reconocieron endpoints.")
            self.l_endpoints_recon.setModel(self.list_endpoint_recon)
            self.scroll_pane_endpoints_recon.revalidate()
            self.scroll_pane_endpoints_recon.repaint()
            
    def prepareFinalEndpoint(self, ):
        threads = []
        # Ciclo endpoints cargados
        for i in range(len(self.endpoints)):
            final_domain = self.domain_field.getText().replace(" ", "")
            final_port = int(self.port_field.getText().replace(" ", ""))
            final_protocol = self.protocol_field.getText().replace(" ", "")
        
            # Obtengo el objeto IHttpService para el dominio deseado
            http_service = self._callbacks.getHelpers().buildHttpService(final_domain, final_port, final_protocol)
            
            # Utilizo este ciclo para armar un endpoint por cada parametro
            for j in range(len(self.endpoints[i].parameters)):
                full_url = self.endpoints[i].endpoint
                body = ""
                param_url = param_body = 0
                # Recorro todos los parametros de este endpoint
                for p in range(len(self.endpoints[i].parameters)):
                    # Utilizo este condicionador para armar un endpoint por cada parametro
                    if p == j:
                        value = self.reflect # Payload
                    else:
                        value = self.endpoints[i].parameters[p].value # Valor normal
                     
                    # Verifico el tipo
                    if self.endpoints[i].parameters[p].type == 1: # tipo Body
                        # Verifico si es el primer parametro
                        if param_body == 0:
                            param_body += 1
                            body = self.endpoints[i].parameters[p].name  + "=" + value
                        else:
                            body += "&" + self.endpoints[i].parameters[p].name + "=" + value
                    else: # tipo URL
                        if param_url == 0:
                            param_url += 1
                            full_url += "?" + self.endpoints[i].parameters[p].name + "=" + value
                        else:
                            full_url += "&" + self.endpoints[i].parameters[p].name  + "=" + value

                            
                # GET /endpoint/with?parameters=1 HTTP/2
                # Host: domain.example.com
                # Cookie: session=example123
                header = ["%s %s %s" % (self.endpoints[i].headers.verb, full_url, self.endpoints[i].headers.protocol), "Host: %s" % (final_domain), self.endpoints[i].headers.cookies] 
                # Resto de header
                for h in self.endpoints[i].headers.the_rest:
                    header.append(h)
                body_bytes = self._helpers.stringToBytes(body)
                # header en formato String[] y body en formato byte[]
                all_req = self._helpers.buildHttpMessage(header, body_bytes)
                # Genero un hilo por cada peticion
                t = threading.Thread(target=self.sendRequest, args=(http_service, all_req, self.endpoints[i]))
                t.start()
                threads.append(t)
        # (Mejora futura) Se podria implementar para que en vez de mostrar todo al terminar, ir mostrando las peticiones y respuestas que van terminando
        for t in threads:
            t.join()
        self.showResults()
            
    def sendRequest(self, http_service, request, endpoint):
            req_resp = self._callbacks.makeHttpRequest(http_service, request)
            self.analizeResponse(req_resp, endpoint)

    def analizeResponse(self, req_resp, endpoint):
        response = self._helpers.bytesToString(req_resp.getResponse())
        request = self._helpers.bytesToString(req_resp.getRequest())
        response_body = response.split("\r\n\r\n")[1]
        # Verifico si se encuentre el payload en la respuesta
        if self.reflect in response_body:
            for p in endpoint.parameters:
                payload = p.name + "=" + self.reflect
                if payload in request:
                    p.isVuln()

    def showResults(self):
        # Loop para recorrer los endpoints
        for i in range(len(self.endpoints)):
            flag = False
            result = ""
            # Loop para recorrer los parametros dentro de cada endpoint
            for param in self.endpoints[i].parameters:
                # Valido si el parametro es vulnerable, si lo es lo muestro
                if param.vuln:
                    if not flag:
                        result = "Posible endpoint vulnerable:  "+ self.endpoints[i].endpoint +"   -->   En el/los parametro/s:  "+ param.name
                        flag = True
                    else:
                        result += ", "+ param.name
            if result != "":
                self.list_endpoint_recon.addElement(result)
        self.list_endpoint_recon.addElement("-- FIN DE ESCANEO --")
        self.l_endpoints_recon.setModel(self.list_endpoint_recon)
        self.scroll_pane_endpoints_recon.revalidate()
        self.scroll_pane_endpoints_recon.repaint()

    def changeDomain(self, event):
        if self.domain != self.domain_field.getText().replace(" ", ""):
            self._callbacks.issueAlert("Dominio seteado -> endpoints restablecidos.")
            self.all_header = []
            self.base_header = []
            self.endpoints = []
            self.params_of_req = []
            self.list_endpoints = DefaultListModel()
            self.l_endpoints.setModel(self.list_endpoints)
            self.scroll_pane_endpoints.revalidate()
            self.scroll_pane_endpoints.repaint()
        self.domain = self.domain_field.getText().replace(" ", "")

    def addEndpoint(self, event):
        verb_url = self.input_field.getText().split(' ')
        if len(verb_url) != 2:
            self._callbacks.issueAlert("Error: Formato incorrecto. (ej: 'GET /example?test=1234')")
            return
        verb = verb_url[0]
        url = verb_url[1]
        all_url = url.split('?')
        if len(all_url) < 2:
            self._callbacks.issueAlert("Error: Debe cargar la URL con parametros. (ej: 'GET /example?test=1234)'")
            return
        endpoint = all_url[0]
        if self.domain == "":
            self._callbacks.issueAlert("Error: Debe cargar el dominio.")
            return
        elif len(self.base_header) == 0:
            self._callbacks.issueAlert("Error: Debe cargar al menos una peticion de manera automatica.")
            return
        header = Header(verb, self.base_header[0], self.base_header[1], self.base_header[2])
        params = all_url[1].split('&')
        all_params = []
        for p in params:
            parts = p.split('=')
            new_param = Parameter(parts[0], parts[1])
            all_params.append(new_param)
        endpoint_obj = Endpoint(header, self.domain, endpoint, all_params)
        self.endpoints.append(endpoint_obj)
        # Actualizo el pane
        self.list_endpoints.addElement(endpoint_obj.endpoint)
        self.l_endpoints.setModel(self.list_endpoints)
        self.scroll_pane_endpoints.revalidate()
        self.scroll_pane_endpoints.repaint()
        # Borro la entrada
        self.input_field.setText("")
            
class Parameter:
    def __init__(self, param_or_name, value=None):
        if value is None:
            self.type = param_or_name.getType()
            self.name = param_or_name.getName()
            self.value = param_or_name.getValue()
        else:
            self.type = 0
            self.name = param_or_name
            self.value = value
        self.vuln = False
      
    def isVuln(self):
        self.vuln = True

class Header:
    def __init__(self, verb, prot, cookies, rest):
        self.verb = verb
        self.protocol = prot
        self.cookies = cookies
        self.the_rest =  rest

class Endpoint:
    def __init__(self, headers, domain, endpoint, params):
        self.headers = headers # Header
        self.domain = domain 
        self.endpoint = endpoint 
        self.parameters = params # Parameter
