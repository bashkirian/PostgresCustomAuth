## Процесс аутентификации в Poco
[пример аутентификации](https://vovkos.github.io/doxyrest-showcase/poco/sphinxdoc/class_Poco_Net_HTTPCredentials.html)
1. Создается объект HTTPCredentials с username и password
2. Отправляется запрос без хедера аутентификации, сервер отвечает 401 с response.
3. У объекта HTTPCredentials вызывается метод authenticate, который создает request для последующей аутентификации
```
creds.authenticate(request, response);
```
4. Отправляется созданный request.
5. Далее уже логика авторизации лежит на нас, в Poco ее нет.

## Процесс создания запроса аутентификации
1. Вызывается функция, принимаюшая запрос, в который будут записываться директивы аутентификации, и уже полученный ответ от сервера. В ней вызывается функция с тем же названием. Но в нее передаем уже распарсенные параметры аутентификации из ответа сервера.
```
void HTTPDigestCredentials::authenticate(clients::http::Request& request, const clients::http::Response& response)
{
	authenticate(request, HTTPAuthenticationParams(response));
}
```
2. Вызывается функция createAuthParams, которая исходя из уже базовых параметров request и директив response строит параметры аутентификации. Далее в существующий запрос методом setCredentials добавляюются созданные директивы аутентификации.
```
// создание запроса аутентификации с распарсенными параметрами аутентификации из ответа сервера
void HTTPDigestCredentials::authenticate(clients::http::Request& request, const HTTPAuthenticationParams& responseAuthParams)
{
	createAuthParams(request, responseAuthParams);
	request.setCredentials(SCHEME, _requestAuthParams.toString());
}
```
## Логика парсинга в конструкторе HTTPAuthenticationParams
1. Запрос с клиента парсится с помощью функции getCredentials, которая ищет хедер авторизации и выцепляет текст ее информации, далее вызывает функцию fromAuthInfo, которая парсит весь текст информации.
2. Парсинг ответа с сервера: ищем хэдер Authentication, и парсим все, что после Digest.
3. Общая функция parse
3.1 Есть enum state, который определяет, в каком состоянии находится парсинг.
```    
// ???
	enum State
	{
		STATE_INITIAL = 0x0100, // 256
		STATE_FINAL = 0x0200, // 512

		STATE_SPACE = STATE_INITIAL | 0, // 256
		STATE_TOKEN = 1,
		STATE_EQUALS = 2,
		STATE_VALUE = STATE_FINAL | 3, // 515
		STATE_VALUE_QUOTED = 4,
		STATE_VALUE_ESCAPE = 5,
		STATE_COMMA = STATE_FINAL | 6 // 518
	};
```
3.2 Итерируемся последовательно по тексту. 
3.2.1 пропускаем пробелы, пока не встретим токен, меняем на состояние парсинга токена.
3.2.2. если встретили '=', меняем состояние на STATE_EQUALS, иначе прибавляем к токену символы.
3.2.3 если встретили после '=' число либо букву, или подчеркивание, то значит нашли значение. если кавычки, то значение в кавычках.
3.2.4 если значение в кавычках, то добавляем токен в мапу, далее ставим состояние парсинга запятой.
3.2.5 если состояние значения: если встретили пробел или запятую, то добавляем токен и ставим состояние пробела или запятой соответственно.
3.2.6 если состояние запятой и встретили запятую, то должен быть потом пробел, ставим состояние пробела. 