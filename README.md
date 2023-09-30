Based on the information provided in the files you shared, I have analyzed the project and compiled a comprehensive description for your project idea. Here's the detailed project description:

Project Title: Advanced Student Management System

Overview:
The Advanced Student Management System is a web-based application designed to streamline and automate the management of students in an educational institution. It provides a robust set of features to efficiently handle student data, such as storing student information, managing departments, tracking academic progress, and facilitating communication between students, faculty, and administrators. The system aims to enhance the overall student management process, improve data accuracy, and optimize administrative tasks.

Key Features:
1. Authentication and Authorization: The system ensures secure access to authorized personnel through user authentication and role-based permissions. It integrates with Sanctum to handle authentication and grants specific permissions, such as "students_management," to control access to student-related functionalities.

2. Student Listing and Filtering: The system allows users to retrieve student records based on various criteria, including department, student number, national number, study year, and current class. It utilizes Laravel's validation rules to validate the request parameters and constructs a query to fetch the relevant student data. The results are presented as a collection of Student Resources.

3. Student Creation and Update: Users can create new student profiles by providing necessary information such as name, contact details, department, and other relevant data. The system validates the input using Laravel's validation rules and saves the student details to the database. Existing student records can also be updated using similar validation and update mechanisms.

4. Department Management: The system supports the management of departments within the educational institution. It associates students with their respective departments using the "department_id" field. Departments can be created, modified, and deleted as required, ensuring accurate categorization and organization of student data.

5. Student Resource and JSON Response: The system utilizes the Student Resource class to format student data into a consistent and structured format. Student records are returned as JSON responses, making it easier to consume and process the data in various client applications.

6. Docker Integration: The system includes a tutorial on obtaining a Docker container's IP address from the host machine. This guide assists developers in leveraging Docker commands and inspecting container network settings, contributing to a seamless integration and deployment process.

7. NestJS Validation: The system provides a tutorial on validating nested objects using the Class Validator library within a NestJS environment. This feature enables the validation of complex data structures and ensures data integrity when handling incoming data.

8. GraphQL Default Values: A tutorial explains how to set default values for input arguments in GraphQL. This feature allows certain fields or arguments to have predefined values if not explicitly provided, enhancing the flexibility and reliability of data queries.

9. NVM for Node.js Version Management: The system includes a guide on using NVM (Node Version Manager) to manage multiple Node.js versions. This helps developers set the default Node.js version for their projects, ensuring compatibility and providing a seamless development experience.

10. Algorithm and Code-related Articles: The system covers various algorithm-related topics, such as choosing the best algorithm for overriding GetHashCode, installing specific versions of Ruby gems, and understanding "Big O" notation. These articles provide valuable insights into algorithmic efficiency, code optimization, and best practices in different programming languages.

11. React Component Development: The system includes tutorials on developing React components, such as a Wordle game using ReactJS and adding multiple classes to a component. These resources aid developers in building interactive and visually appealing user interfaces using React.

12. Documentation: The project emphasizes the importance of documentation, specifically the README.md file. It provides a comprehensive guide on setting up and using the project, showcasing its features, and assisting developers in understanding the codebase and its dependencies.

By combining these features, tutorials, and documentation, the Advanced Student Management System offers a powerful and user-friendly solution for educational institutions to efficiently manage student data, streamline administrative tasks, and foster effective communication within the institution. The project demonstrates proficiency in PHP (utilizing Laravel), Docker, NestJS, GraphQL, Node.js, algorithms, Ruby, and React, showcasing a diverse skill set and a deep understanding of modern web development technologies.
## Contents
(contains parts of my code)

[Tables and relations](#tables-and-relations)

- [Authentication](#authentication)
    - [Guards](#Guards)
      - [Guards Definition](#guards-definition)
      - [Guards building steps](#guards-building-steps)
    - [LogIn](#login)
      - [Login with API route](#login-with-api-route)
      - [Login with web route](#login-with-web-route)
    - [Authentication](#authentication)
  

[PermissionSeeder Class](#PermissionSeeder)

[Add permission to a specific role](#role-permission)

[Get user permissions](#user-permissions)

[Add teacher to a specific material](#add-teacher)

[Store observation](#store-observation)

[Opened halls](#opened-halls)

[Students list](#students)


### **tables-and-relations**

![Logo](/images/tables-relations.png)

<a href="/moraqabat.pdf" target="_blank">Open PDF Document</a>

[🔝 Back to contents](#contents)


### **guards-definition**

In the context of web application security, guards are an essential component of authentication systems. They provide a way to authenticate and authorize users based on their roles or permissions. Guards help ensure that only authenticated users with the necessary privileges can access certain resources or perform specific actions within an application.

Here are the key aspects of guards and their role in web application security:

1. **Authentication**:
   Guards handle the authentication process, which verifies the identity of a user. When a user attempts to log in or access a protected resource, the guard authenticates their credentials, such as username and password. If the credentials are valid, the user is considered authenticated and gains access to the application.

2. **Authorization**:
   Guards also handle the authorization process, which determines whether an authenticated user has the necessary permissions to perform a specific action or access a particular resource. Based on the user's role, permissions, or any other defined criteria, guards enforce access control and restrict unauthorized actions or resource access.

3. **Middleware Integration**:
   Guards seamlessly integrate with middleware in web frameworks. Middleware acts as a filter or interceptor for incoming requests, allowing  to intercept and inspect requests before they reach the intended route or controllers.


[🔝 Back to contents](#contents)

### **guards-building-steps**

The overall steps for building guards:

1. [Configure Guards](#configure-guards): Define the guards in the `config/auth.php` configuration file. Specify the driver (e.g., session, token, or passport) and associate each guard with an authentication provider.

2. [Implement Guard-Specific Middleware](#guards-middlewares): For custom logic for the guards, create guard-specific middleware classes. Middleware intercepts requests and can be used for authentication, authorization, or any other processing before the request reaches the intended route or controller.

3. [Register Middleware](#register-middlewares): In the `app/Http/Kernel.php` file, register the guard-specific middleware classes in the `$routeMiddleware` property. Assign a unique key to each middleware class, which will be used when specifying middleware for routes or controllers.

4. [Apply Middlewares to Routes or Controllers](#apply-middleware-example): Use the registered middleware in the routes or controllers to enforce authentication and authorization. Specify the middleware using the assigned keys in the `$routeMiddleware` property.

5. **Redirect or Respond**: Depending on the authentication and authorization outcomes, redirect the user to the appropriate routes or controllers, or respond with appropriate error messages or status codes. Laravel provides helper methods like `redirect()` and `abort()` for these purposes.

[🔝 Back to contents](#contents)

### **configure-guards**

`config\auth.php:`

This configuration file allows to authenticate and authorize users based on different guard types and provide customized authentication logic for each guard.

```php
'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    'user' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    'observer' => [
        'driver' => 'session',
        'provider' => 'observers',
    ],
],
.
.
.
    'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\Models\User::class,
    ],
    'observers' => [
        'driver' => 'eloquent',
        'model' => App\Models\Observer::class,
    ],
],
```
The `guards` array defines the authentication guards available in my application. Each guard is associated with a specific driver and provider.

Guards I defined:

1. **web**:
   - Driver: `'session'`
   - Provider: `'users'`

   This guard is the default guard for web-based authentication. It uses the session driver to store the user's authentication status and is associated with the `'users'` provider, which is an Eloquent-based provider.

2. **user**:
   - Driver: `'session'`
   - Provider: `'users'`

   This guard is a custom guard named `'user'`. It also uses the session driver and is associated with the `'users'` provider.

3. **observer**:
   - Driver: `'session'`
   - Provider: `'observers'`

   This guard is another custom guard named `'observer'`. It utilizes the session driver and is associated with the `'observers'` provider.


The `providers` array defines the authentication providers used by the guards. Each provider specifies the driver and model associated with it.

Providers I defined:

1. **users**:
   - Driver: `'eloquent'`
   - Model: `App\Models\User::class`

   This provider is associated with the `'users'` guard and uses the Eloquent driver to retrieve user information. The `model` property specifies the User model class for this provider.

2. **observers**:
   - Driver: `'eloquent'`
   - Model: `App\Models\Observer::class`

   This provider is associated with the `'observers'` guard and also uses the Eloquent driver. It specifies the Observer model class for this provider.

[🔝 Back to contents](#contents)

### **guards-middlewares**

I defined two middlewares, ObservationsGuest and ObservationsAuth.

`app\Http\Middleware\ObservationsGuest.php:`

```php
class ObservationsGuest
{
    public function handle(Request $request, Closure $next)
    {
        $observer = Auth::guard('observer')->user();
        $user = Auth::guard('user')->user();

        if ($user)
        return redirect()->route('user.home');
        if ($observer)
        return redirect()->route('observer.home');

        return $next($request);
    }
}
```

The `ObservationsGuest` middleware checks for an authenticated user and observer using their respective guards. It redirects the request based on the authentication status, either to the user's home page or the observer's home page. If no user or observer is authenticated, the request proceeds to the next middleware or the final request handler.

1. The middleware first checks if there is an authenticated user using the `'user'` guard by accessing `Auth::guard('user')->user()`.
   - If an authenticated user exists, it redirects the request to the `'user.home'` route using `redirect()->route('user.home')`.
   - This means that if a user is already authenticated, they will be redirected to the `'user.home'` route, assuming it is the home page for authenticated users.

2. If there is no authenticated user, the middleware then checks if there is an authenticated observer using the `'observer'` guard by accessing `Auth::guard('observer')->user()`.
   - If an authenticated observer exists, it redirects the request to the `'observer.home'` route using `redirect()->route('observer.home')`.
   - This means that if an observer is authenticated but not a user, the request will be redirected to the `'observer.home'` route, assuming it is the home page for authenticated observers.

3. If neither a user nor an observer is authenticated, the middleware allows the request to proceed to the next middleware or the final request handler using `$next($request)`.
   - This means that if no user or observer is authenticated, the request will continue to the next middleware in the pipeline or reach the final request handler for further processing.


`app\Http\Middleware\ObservationsAuth.php:`

```php
class ObservationsAuth
{
    public function handle(Request $request, Closure $next, $type)
    {
        $observer = Auth::guard('observer')->user();
        $user = Auth::guard('user')->user();
        
        if (!$observer && !$user && $type == 'observer')
            return redirect()->route('observer.login');

        if (!$observer && !$user && $type == 'user')
            return redirect()->route('user.login');

        if ($observer && !$user && $type != 'observer')
            return abort('403');

        if ($user && !$observer && $type != 'user')
            return abort('403');

        return $next($request);
    }
}
```

The `ObservationsAuth` middleware checks for the authentication status of observers and users based on their respective guards. It redirects or aborts the request based on the specified authentication type (`'observer'` or `'user'`) and the authentication status. If an observer or user is authenticated but doesn't match the desired authentication type, the request will be aborted. If no observer or user is authenticated, the middleware redirects the request to the corresponding login page. If none of these conditions are met, the request proceeds to the next middleware or the final request handler.

1. The middleware first checks if there is an authenticated observer using the `'observer'` guard
by accessing `Auth::guard('observer')->user()`.
   - If no observer is authenticated and no user is authenticated, and the specified `$type` is `'observer'`, it redirects the request to the `'observer.login'` route using `redirect()->route('observer.login')`.
      - This means that if no observer or user is authenticated, and the desired authentication type is `'observer'`, the request will be redirected to the `'observer.login'` route, assuming it is the login page for observers.
   - If no observer is authenticated and no user is authenticated, and the specified `$type` is `'user'`, it redirects the request to the `'user.login'` route using `redirect()->route('user.login')`.
      - This means that if no observer or user is authenticated, and the desired authentication type is `'user'`, the request will be redirected to the `'user.login'` route, assuming it is the login page for users.

2. If an observer is authenticated but no user is authenticated, and the specified `$type` is not `'observer'`, it aborts the request with a `403` status code using `abort('403')`.
   - This means that if an observer is authenticated but the desired authentication type is not `'observer'`, the request will be aborted with a `403 Forbidden` response.

3. If a user is authenticated but no observer is authenticated, and the specified `$type` is not `'user'`, it aborts the request with a `403` status code using `abort('403')`.
   - This means that if a user is authenticated but the desired authentication type is not `'user'`, the request will be aborted with a `403 Forbidden` response.

4. If none of the above conditions are met, the middleware allows the request to proceed to the next middleware or the final request handler using `$next($request)`.
   - This means that if no redirection or abort occurs, the request will continue to the next middleware in the pipeline or reach the final request handler for further processing.

[🔝 Back to contents](#contents)

### **register-middlewares**

`app\Http\Kernel.php:`

```php
.
.
    protected $routeMiddleware = [

        ...

        'ob_auth' => \App\Http\Middleware\ObservationsAuth::class,
        'ob_guest' => \App\Http\Middleware\ObservationsGuest::class,

        ...

    ];
```

By registering these middleware aliases in the `$routeMiddleware` property, It allows to easily reference and apply the corresponding middleware classes to specific routes or controller actions.

[🔝 Back to contents](#contents)

### **apply-middleware-example**

`app\Http\Controllers\ObserversAuthController.php:`

```php
class ObserversAuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('ob_guest')->only('login','do_login');
        $this->middleware('ob_auth:observer')->only('logout');
    }

    public function login()
    {
        $observer = Auth::guard('observer')->user();
        if($observer)
            return redirect()->route('observer.home');
        $observers = Observer::orderBy('name')->get();
        return view('observers.login')->with("observers",$observers);
    }

    public function logout()
    {
        Auth::guard('observer')->logout();
        return redirect()->route('home');
    }
}
```
The `ObserversAuthController` demonstrates the usage of middleware in a controller. The `ObservationsGuest` middleware is applied to the `'login'` and `'do_login'` actions, ensuring that only guests (non-authenticated users) can access those actions. The `ObservationsAuth` middleware is applied to the `'logout'` action, ensuring that only authenticated observers can access the logout action.

**__construct() Method**: 

This method is the constructor of the controller. It is called when an instance of the controller is created. In the constructor, middleware is applied to specific controller actions using the `middleware` method.

1. `$this->middleware('ob_guest')->only('login','do_login');`:
   This middleware, `'ob_guest'`, is applied only to the `'login'` and `'do_login'` actions. It means that when these actions are accessed, the `ObservationsGuest` middleware will be executed before the action code.

2. `$this->middleware('ob_auth:observer')->only('logout');`:
   This middleware, `'ob_auth'`, is applied only to the `'logout'` action. Additionally, it receives a parameter `'observer'`, which specifies the desired authentication type. This middleware is associated with the `ObservationsAuth` middleware class. It means that when the `'logout'` action is accessed, the `ObservationsAuth` middleware will be executed with the parameter `'observer'` before the action code.

[🔝 Back to contents](#contents)

### **login-with-api-route**

`routes\api.php:`

```php
Route::post('login', [AuthController::class, 'login']);
```

`app\Http\Controllers\Api\AuthController.php:`

```php
public function __construct()
{
    $this->middleware('auth:sanctum')->only(['logout', 'user']);
}
```

The `__construct()` method is part of the `AuthController` class and is executed when an instance of the class is created. It is responsible for setting up the middleware for authentication using Sanctum.

`$this->middleware('auth:sanctum')->only(['logout', 'user'])` This line specifies that the `auth:sanctum` middleware should be applied only to the `logout` and `user` methods of the controller. This means that before accessing these methods, the user must be authenticated using the Sanctum authentication guard.

The `auth:sanctum` middleware provided by Laravel Sanctum validates the user's authentication credentials and ensures that the user is logged in before proceeding with the requested actions. By applying this middleware to specific methods, you can restrict access to those methods only to authenticated users, providing an extra layer of security for sensitive operations.

```php
public function login(Request $request)
{
    $request->validate([
        'username' => 'required',
        'password' => ['required', 'min:6'],
        'remember' => ['boolean'],
    ]);

    if (Auth::attempt(['username' => $request->username, 'password' => $request->password])) {
        $user = to_user(Auth::user());
        $token = $user->createToken('Sanctum', [])->plainTextToken;
        if ($request->remember && !$user->remember_token) {
            $user->remember_token = Str::random(40);
            $user->save();
        }
        return response()->json([
            'user' => new UserResource($user),
            'remember_token' => $user->remember_token,
            'token' => $token,
        ], 200);
    }

    return response()->json([
        'message' => 'Username or password is incorrect.',
        'errors' => [
            'username' => ['Username or password is incorrect.']
        ]
    ], 422);
}
```

The `login()` function handles the login process for the API:

1. The function first validates the incoming request data using the `validate()` method. It ensures that the `username` field is required, the `password` field has a minimum length of 6 characters, and the `remember` field is a boolean value.

2. If the validation passes, it proceeds to the authentication step using `Auth::attempt()`. It attempts to authenticate the user by matching the provided `username` and `password` with the user credentials stored in the database.

3. If the authentication attempt is successful (`Auth::attempt()` returns `true`), it performs the following actions:
   - Retrieves the authenticated user using `Auth::user()` and converts it to a custom user object using the `to_user()` function. 
   - Generates an access token for the user using `$user->createToken('Sanctum', [])->plainTextToken`. The token is associated with the 'Sanctum' token name.
   - If the `remember` field is set to `true` and the user doesn't have a `remember_token` already, it generates a random remember token using `Str::random(40)` and saves it to the user model.
   - Returns a JSON response with the following data:
     - `'user'`: The serialized user object using the `UserResource` class to format the user attributes.
     - `'remember_token'`: The remember token if it was generated, or `null` if not applicable.
     - `'token'`: The plain text representation of the generated access token.

4. If the authentication attempt fails (`Auth::attempt()` returns `false`), it returns a JSON response indicating the error:
   - `'message'`: A message indicating that the username or password is incorrect.
   - `'errors'`: An array of errors with the `'username'` field containing an error message.


[🔝 Back to contents](#contents)

### **login-with-web-route**

`routes\web.php:`

```php
Route::get('observer/login', [ObserversAuthController::class, 'login'])->name('observer.login');
Route::post('observer/login', [ObserversAuthController::class, 'do_login'])->name('login');
```
`app\Http\Controllers\ObserversAuthController.php:`

```php
public function __construct()
{
    $this->middleware('ob_guest')->only('login','do_login');
    $this->middleware('ob_auth:observer')->only('logout');
}
```

The `__construct()` method in the `ObserversAuthController` class sets up middleware groups for specific controller methods.

1. `$this->middleware('ob_guest')->only('login','do_login')`:
   - This middleware group, named `'ob_guest'`, is applied only to the `login` and `do_login` methods of the controller.
   - The purpose of this middleware group is to allow only guest users (non-authenticated users) to access these login-related methods.
   - It ensures that users who are already authenticated are redirected or blocked from accessing the login routes.

2. `$this->middleware('ob_auth:observer')->only('logout')`:
   - This middleware group, named `'ob_auth:observer'`, is applied only to the `logout` method of the controller.
   - The purpose of this middleware group is to restrict access to the `logout` method to only authenticated users with the 'observer' role.
   - It ensures that only users who are authenticated as observers can perform the logout action, providing access control based on user roles.

By using these middleware configurations in the constructor, the `login` and `do_login` methods are accessible only to guest users, preventing authenticated users from accessing the login routes again. On the other hand, the `logout` method is accessible only to authenticated users with the 'observer' role, ensuring that unauthorized users cannot log out. These middleware groups help control access privileges and enhance the security and functionality of the login and logout processes in the web routes.

```php
public function login()
{
    $observer = Auth::guard('observer')->user();

    if ($observer) {
        return redirect()->route('observer.home');
    }

    $observers = Observer::orderBy('name')->get();

    return view('observers.login')->with("observers", $observers);
}
```

The `login()` function handles the logic for the login process in the context of observers. Here's a breakdown of the code:

1. It first checks if there is already an authenticated observer user using the `Auth::guard('observer')->user()` method.
   - If an observer user is already logged in, the function redirects them to the 'observer.home' route. This prevents authenticated users from accessing the login page again.

2. If there is no authenticated observer user, it retrieves a collection of observers from the database, ordered by their names, using the `orderBy` query.
   - The collection of observers is stored in the variable `$observers`.

3. It then returns the 'observers.login' view, passing the `$observers` variable to the view as the "observers" parameter.
   - This allows the login view to access the list of observers and present them in the login form.

```php
public function do_login(Request $request)
{
    $request->validate([
        'observer_id' => ['required', 'exists:observers,id'],
        'password' => ['required', 'string']
    ]);

    $observer = Observer::where('id', $request->observer_id)->first();

    if (!$observer->password) {
        return back()->withInput()->with('error', "المعلومات الشخصية للمراقب غير كاملة.\n يرجى إرسال صورة لوجهي الهوية الشخصية مع القسم والتوصيف الوظيفي والمرتبة العلمية على رقم واتساب التالي: <a href='https://wa.me/0985415539' target='_blank'>0985415539</a>");
    }

    if (!Hash::check($request->password, $observer->password)) {
        return back()->withInput()->with('error', ' كلمة المرور غير صحيحة');
    }

    Auth::guard('observer')->login($observer);
    return redirect()->route('observer.home');
}
```

The `do_login()` function handles the submission of the login form for observers

1. It first validates the request data using the `validate()` method:
   - The `'observer_id'` field is required and must exist in the `'observers'` table.
   - The `'password'` field is required and must be a string.

2. It retrieves the observer from the database based on the provided observer ID using the `where('id', $request->observer_id)->first()` query.

3. It checks if the observer's password is empty (`!$observer->password`).
   - If the password is empty, it returns back to the login form with an error message indicating that the observer's personal information is incomplete.
   - The error message also includes instructions to contact a specific WhatsApp number for further action.

4. It uses `Hash::check($request->password, $observer->password)` to compare the provided password with the hashed password stored for the observer.
   - If the password does not match, it returns back to the login form with an error message indicating that the password is incorrect.

5. If the provided observer ID and password are valid, it logs in the observer using `Auth::guard('observer')->login($observer)`.
   - The observer is now authenticated.

6. It redirects the observer to the 'observer.home' route, indicating a successful login.

The login and do_login functions work together to handle the login process for observers, ensuring proper validation, authentication, and redirecting based on the authentication status and provided credentials.

[🔝 Back to contents](#contents)
### PermissionSeeder

`database\seeders\PermissionSeeder.php`

```php
class PermissionSeeder extends Seeder {
    public function run() {
        $permissions = Permission::all()->pluck('name')->toArray();
        
        // Create missing permissions if they don't exist
        if(!in_array('users_management', $permissions))
            Permission::create(['name' => 'users_management']);
        if(!in_array('permissions_management', $permissions))
            Permission::create(['name' => 'permissions_management']);
        // ... and so on for other permissions
        
        $roles = Role::all()->pluck('name')->toArray();
        
        // Create or retrieve 'super_admin' role
        if(!in_array('super_admin', $roles))
            $super_admin_role = Role::create(['name' => 'super_admin']);
        else
            $super_admin_role = Role::where('name', 'super_admin')->first();
        
        // Create or retrieve 'admin' role
        if(!in_array('admin', $roles))
            $admin_role = Role::create(['name' => 'admin']);
        else
            $admin_role = Role::where('name', 'admin')->first();
        
        // Assign 'super_admin' role to 'super_admin' user
        $super_admin_user = User::where('username','super_admin')->first();
        if($super_admin_user)
            $super_admin_user->assignRole($super_admin_role);
        
        // Assign 'admin' role to 'admin' user
        $admin_user = User::where('username','admin')->first();
        if($admin_user)
            $admin_user->assignRole($admin_role);
        
        $permissions = Permission::all();
        
        // Give 'super_admin' role permission to all existing permissions
        foreach($permissions as $permission)
            $super_admin_role->givePermissionTo($permission);
    }
}
```

The `PermissionSeeder` class is responsible for populating the database with initial permission and role data. It creates or retrieves specific permissions and roles, assigns roles to users, and gives the `super_admin` role permission to all existing permissions in the system. This seeder class is typically used to seed the initial data in the database for permissions and roles.

The code performs the following actions:

1. Retrieves all existing permissions from the `Permission` model and stores their names in an array using the `pluck` method.
2. Checks if each permission (included in each `if` statement) exists in the array of permissions. If not, it creates a new permission with the corresponding name (e.g., `'users_management'`) using the `create` method of the `Permission` model.
3. Repeats the above step for each of the following permissions: `'permissions_management'`, `'departments_management'`, `'positions_management'`, `'observers_management'`, `'note_templates_management'`, `'desire_types_management'`, `'desires_management'`, `'exam_days_management'`, `'collages_management'`, `'halls_management'`, `'materials_management'`, and `'observations_management'`.
4. Retrieves all existing roles from the `Role` model and stores their names in an array using the `pluck` method.
5. Checks if a role named `'super_admin'` exists in the array of roles. If not, it creates a new role with the name `'super_admin'` using the `create` method of the `Role` model. If the role already exists, it retrieves the existing role using the `where` method.
6. Repeats the above step for a role named `'admin'`.
7. Retrieves the user with the username `'super_admin'` using the `User` model. If the super admin user exists, it assigns the `'super_admin'` role to the user using the `assignRole` method.
8. Retrieves the user with the username `'admin'` using the `User` model. If the admin user exists, it assigns the `'admin'` role to the user using the `assignRole` method.
9. Retrieves all permissions from the `Permission` model.
10. Iterates over each permission and gives the `'super_admin'` role permission to each permission using the `givePermissionTo` method.

[🔝 Back to contents](#contents)

### **role-permission**

`app\Http\Controllers\PermissionsController.php`

```php
public function __construct()
{
    $this->middleware('auth:sanctum');
    $this->middleware('can:permissions_management');
}
```

The constructor method applies two middlewares:

- `auth:sanctum`: This middleware is responsible for authenticating the user using Sanctum. Sanctum is a Laravel package that provides a simple, lightweight authentication system for APIs. It allows users to authenticate using API tokens.

- `can:permissions_management`: This middleware checks if the authenticated user has the necessary permission (`permissions_management`) to access the corresponding route or method.

```php
public function add_role_permission(Role $role, Request $request)
{
    $request->validate([
        'name' => ['required', 'exists:permissions,name'],
    ]);
    $role->givePermissionTo($request->name);
    return PermissionResource::collection($role->permissions);
}
```

The `add_role_permission()` method is responsible for adding a permission to a specified role and returning a collection of permissions using a resource class for formatting.

Description of code lines:

1. The method starts by validating the incoming request data using the `validate` method. It checks if the `name` field is required and exists in the `permissions` table with the `name` column.

2. If the validation passes, the method calls the `givePermissionTo` method on the `$role` object. This method, provided by a package, assigns the specified permission (`$request->name`) to the role.

3. Finally, the method returns a collection of `PermissionResource` objects. It appears that `PermissionResource` is a resource class used to transform and format the permissions associated with the role.

[🔝 Back to contents](#contents)

### **user-permissions**

`app\Http\Controllers\Api\UsersController.php`

```php
public function __construct()
{
    $this->middleware('auth:sanctum');
    $this->middleware('can:users_management');
}
```

The constructor method applies two middlewares:

- `auth:sanctum`: This middleware is responsible for authenticating the user using Sanctum. Sanctum is a Laravel package that provides a simple, lightweight authentication system for APIs. It allows users to authenticate using API tokens.

- `can:users_management`: This middleware checks if the authenticated user has the necessary permission (`users_management`) to access the corresponding route or method.

```php
public function get_users_permissions(User $user)
{
    $roles_ids = $user->roles->pluck('id');
    $permissions_ids = DB::table('role_has_permissions')->whereIn('role_id', $roles_ids)->get()->unique('permission_id')->pluck('permission_id');
    $permissions = Permission::whereIn('id', $permissions_ids)->get();
    return PermissionResource::collection($permissions);
}
```

The `get_users_permissions()` method is responsible for retrieving the roles associated with a user, fetching the unique permission IDs from the roles, retrieving the corresponding permissions, and returning them as a collection of formatted `PermissionResource` objects.

Description of code lines:

1. The method starts by retrieving the role IDs associated with the `$user` using the `pluck` method on the `$user->roles` relationship.

2. Next, it queries the `role_has_permissions` table using the `whereIn` method to fetch the rows where the `role_id` is in the `$roles_ids` array. It retrieves all the rows and ensures that only unique `permission_id` values are returned using the `unique` method.

3. The method then retrieves the permissions corresponding to the `permissions_ids` using the `Permission` model and the `whereIn` method.

4. Finally, it returns a collection of `PermissionResource` objects using the `PermissionResource::collection` method to format the permissions.

[🔝 Back to contents](#contents)

### **add-teacher**

#### app\Http\Controllers\Api\MaterialsController.php:

```php
public function add_teacher(Material $material, Request $request)
{
    $request->validate([
        'observer_id'   => ['required', 'exists:observers,id'],
    ]);
    $material->teachers()->attach($request->observer_id);
    return $material->teachers()->pluck('name');
}
```

1. It validates the request data using the `validate` method. In this case, it ensures that the `observer_id` field is required and exists in the `observers` table.

2. After validating the request, it associates the specified observer with the given material by calling the `attach` method on the `teachers` relationship of the `$material` object.

3. Finally, it returns the names of all the teachers associated with the material by calling the `pluck` method on the `teachers` relationship.

The `add_teacher` method is used to manage the relationship between materials and teachers, allowing materials to have multiple teachers.


`app\Models\Material.php`

```php
public function teachers()
{
    return $this->belongsToMany(Observer::class, 'material_teachers', 'material_id', 'teacher_id');
}
```

The `teachers` method is establishes a many-to-many relationship between the `Material` model and the `Observer` model. It uses the `belongsToMany` method and specifies the following parameters:

- `Observer::class`: The related model class for teachers, in this case, the `Observer` model.
- `'material_teachers'`: The name of the pivot table that represents the relationship between materials and teachers.
- `'material_id'` and `'teacher_id'`: The foreign key columns in the pivot table that correspond to the material and teacher IDs, respectively.

`database\migrations\2022_10_26_134508_create_material_teachers_table.php`

```php
Schema::create('material_teachers', function (Blueprint $table) {
    $table->id();
    $table->foreignId('material_id')->constrained('materials');
    $table->foreignId('teacher_id')->constrained('observers');
    $table->unique(['material_id','teacher_id']);
    $table->timestamps();
});
```

- `material_id`: A foreign key column referencing the `materials` table.
- `teacher_id`: A foreign key column referencing the `observers` table.
- `unique(['material_id','teacher_id'])`: Defines a unique constraint on the combination of `material_id` and `teacher_id` columns to ensure that each material can have a unique teacher.

[🔝 Back to contents](#contents)

### **store-observation**

`app\Http\Controllers\Api\ObservationsController.php`

```php
public function store(Request $request)
{
    $request->validate([
        'exam_day_id'   => ['required', 'exists:exam_days,id'],
        'exam_period'   => ['required', 'in:1,2,3'],
        'hall_id'       => ['required', 'exists:halls,id'],
        'observer_id'   => ['required', ValidationRule::exists('observers', 'id')->where('ob_active', true)],
        'force'         => ['boolean'],
    ]);

    $exam_day = ExamDay::find($request->exam_day_id);
    $periods = $exam_day->periods_count;
    $rule = 'in:1' . ($periods >= 2 ? ',2' : '') . ($periods >= 3 ? ',3' : '');

    $request->validate([
        'exam_period'   => [$rule],
    ]);

    $observer = Observer::find($request->observer_id);

    // Check if the observer has remaining observations
    if ($observer->ob_remain <= 0 && !$request->force) {
        throw new BadRequestException("The selected observer has full observations!");
    }

    $observation = Observation::create([
        'exam_day_id' => $request->exam_day_id,
        'exam_period' => $request->exam_period,
        'hall_id'     => $request->hall_id,
        'observer_id' => $request->observer_id,
    ]);

    $observer->update([
        'ob_finished' => DB::raw('ob_finished + 1'),
        'ob_remain'   => DB::raw('ob_remain - 1'),
    ]);

    return response()->json(new ObservationResource($observation), 201);
}
```

The `store` method is responsible for storing a new observation. It follows the standard Laravel method signature, taking a `Request` object as a parameter and returning a JSON response.

The method begins by validating the request data using the `validate` method. It ensures that the required fields (`exam_day_id`, `exam_period`, `hall_id`, `observer_id`) are present and meet the specified validation rules. The `force` field is validated as a boolean.

Next, the code retrieves the associated `ExamDay` instance based on the provided `exam_day_id` using the `find` method.

A validation rule string (`$rule`) is constructed for the `exam_period` field based on the number of periods available for the exam day.

The code checks if the selected observer has remaining observations. If the observer has no remaining observations and the `force` parameter is not set, a `BadRequestException` is thrown with an appropriate message.

If the observer has remaining observations or the `force` parameter is set, a new `Observation` instance is created using the `create` method. The observation is populated with the provided data: `exam_day_id`, `exam_period`, `hall_id`, and `observer_id`.

After creating the observation, the observer's attributes are updated to reflect the change in the number of finished observations (`ob_finished`) and remaining observations (`ob_remain`). This is done using the `update` method and the `DB::raw` expression to increment `ob_finished` by 1 and decrement `ob_remain` by 1.

Finally, the created observation is transformed into a [ObservationResource class](#ObservationResource) instance, and the response is returned as JSON with a HTTP status code of 201 (Created).

### **ObservationResource**

`app\Http\Resources\ObservationResource.php`

```php
class ObservationResource extends JsonResource
{
    public function toArray($request)
    {
        return [
            'id'              => $this->id,
            'exam_day_id'     => $this->exam_day_id,
            'hall_id'         => $this->hall_id,
            'observer_id'     => $this->observer_id,
            'exam_period'     => $this->exam_period,
            'exam_day'        => [
                'id'          => $this->exam_day->id,
                'date'        => $this->exam_day->date,
            ],
            'hall'            => [
                'id'          => $this->hall->id,
                'name'        => $this->hall->name,
                'collage'     => new CollageResource($this->hall->collage),
            ],
            'observer'        => [
                'id'          => $this->observer->id,
                'name'        => $this->observer->name,
                'rank'        => $this->observer->rank,
                'ob_type'     => $this->observer->ob_type,
                'ob_count'    => $this->observer->ob_count,
                'ob_remain'   => $this->observer->ob_remain,
                'ob_finished' => $this->observer->ob_finished,
            ],
        ]; 
    }
}
```
The `ObservationResource` class extends the `JsonResource` class and is used to transform an observation model into a JSON array.

The `toArray` method is overridden to define the structure of the transformed array. It includes the following fields:

- `id`: The observation's ID.
- `exam_day_id`: The ID of the associated exam day.
- `hall_id`: The ID of the associated hall.
- `observer_id`: The ID of the associated observer.
- `exam_period`: The exam period of the observation.
- `exam_day`: An array representing the associated exam day, containing the `id` and `date` fields.
- `hall`: An array representing the associated hall, containing the `id`, `name`, and `collage` fields. The `collage` field is transformed using the `CollageResource` class (a similar class that transforms an collage model into a JSON array).
- `observer`: An array representing the associated observer information.

[🔝 Back to contents](#contents)

### **opened-halls**

`app\Http\Controllers\Api\ResultsController.php`

```php
public function opened_halls()
{
    $opened_halls = OpenedHall::with(['hall', 'exam_day'])->get();

    $results = [];
    foreach ($opened_halls as $opened_hall) {
        $exam_day_id = (int) $opened_hall->exam_day_id;
        $exam_period = (int) $opened_hall->exam_period;

        if (!isset($results[$exam_day_id])) {
            $results[$exam_day_id] = [
                'exam_day' => new ExamDayResource($opened_hall->exam_day),
                'periods' => [],
            ];
        }

        if (!isset($results[$exam_day_id]['periods'][$exam_period])) {
            $results[$exam_day_id]['periods'][$exam_period] = [];
        }

        $results[$exam_day_id]['periods'][$exam_period][] = [
            'hall' => new HallResource($opened_hall->hall),
            'opened_sections' => (int) $opened_hall->opened_sections,
        ];
    }

    ksort($results);
    foreach ($results as $key => $value) {
        ksort($results[$key]['periods']);
    }

    return $results;
}
```

The `opened_halls` function retrieves information about opened halls for exams, organizes the data by exam days and periods, and returns the sorted results in an array format. This structured representation allows for efficient handling and retrieval of the opened hall information.

The function begins by fetching all instances of the `OpenedHall` model from the database, eager loading their associated `hall` and `exam_day` relationships.

The function iterates over each `$opened_hall` in the `$opened_halls` collection using a `foreach` loop.

For each opened hall, the exam day ID and exam period are extracted and casted to integers for consistency.

The function checks if an entry for the exam day already exists in the `$results` array. If not, a new entry is created with the exam day and an empty array for periods.

Similarly, the function checks if an entry for the exam period already exists within the exam day's periods. If not, a new empty array is created.

The opened hall information, including the hall resource and the number of opened sections, is added to the corresponding period array.

After processing all opened halls, the `$results` array is sorted based on the exam day ID using `ksort()`. Additionally, each period array within the exam days is sorted using `ksort()` to ensure an organized representation.

Finally, the sorted and structured `$results` array is returned, providing information about opened halls grouped by exam days and periods.

[🔝 Back to contents](#contents)

### **students**

`app\Http\Controllers\Api\StudentController.php`

```php
public function index(Request $request)
{
    $request->validate([
        'department_id'   => ['exists:departments,id'],
        'student_number'  => ['string'],
        'national_number' => ['string'],
        'study_year'      => ['string'],
        'current_class'   => ['in:1,2,3,4,5'],
    ]);

    $q = Student::query();

    if ($request->department_id) {
        $q->where('department_id', $request->department_id);
    }

    if ($request->student_number) {
        $q->where('student_number', $request->student_number);
    }

    if ($request->national_number) {
        $q->where('national_number', $request->national_number);
    }

    if ($request->study_year) {
        $q->where('study_year', $request->study_year);
    }

    if ($request->current_class) {
        $q->where('current_class', $request->current_class);
    }

    $students = $q->get();

    return StudentResource::collection($students);
}
```

The `index` function handles the search functionality for retrieving students based on various criteria provided in the request. It applies the specified filters to the database query, retrieves the matching students, and returns them as a collection of transformed resources.

The function begins by validating the request parameters using the `validate` method to ensure they meet the specified rules.

Next, a query builder instance for the `Student` model is created using the `query` method.

The function applies filters to the query based on the provided parameters such as `department_id`, `student_number`, `national_number`, `study_year`, and `current_class`. Each filter is applied conditionally to the query if the corresponding parameter is present in the request.

After applying the filters, the query is executed using the `get` method, and the resulting collection of matching students is stored in the `$students` variable.

Finally, the function transforms the student objects into a resource representation using the `StudentResource` class and returns the transformed collection as a JSON response.

[🔝 Back to contents](#contents)