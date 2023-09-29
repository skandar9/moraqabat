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

[Tables and relations](#tables-and-relations)

[Authentication](#authentication)

[PermissionSeeder Class](#PermissionSeeder)

[Add permission to a specific role](#role-permission)

[Get user permissions](#user-permissions)

[Add teacher to a specific material](#add-teacher)

[Store observation](#store-observation)

[Opened halls](#opened-halls)

[Students list](#students)


### **tables-and-relations**

![Logo](/images/tables-relations.png)

[Link Text](/moraqabat.pdf){:target="_blank"}

[🔝 Back to contents](#contents)

### **authentication**

1-Using Api routes: 

routes\api.php:

```php
Route::post('login', [AuthController::class, 'login']);
```

app\Http\Controllers\Api\AuthController.php:

The constructor, this function is part of a controller class and is responsible for setting up themiddleware for authentication using Laravel Sanctum.
This middleware ensures that the user is authenticated using the Sanctum authentication guardbefore accessing the methods.
The $this->middleware('auth:sanctum')->only(['logout', 'user']); line specifies that the'auth:sanctum' middleware should be applied only to the 'logout' and 'user' methods.

```php
    public function __construct()
    {
        $this->middleware('auth:sanctum')->only(['logout', 'user']);
    }
```

The login() function, It  validates the incoming request data, including the username, password, and remember option. If the  authentication attempt is successful, it generates an access token using Laravel Sanctum and returns a JSON response with the authentication user "Auth::user()" details, remember token (if applicable), and the access token. If the  authentication attempt fails, it returns a JSON response indicating the error.

The Auth::attempt() method at line 78 is attempting to authenticate the user using the provided username and password.
The method takes an array of credential key-value pairs as its argument, where the keys represent the user attributes ('username', 'password') and the values correspond to the provided input values from the request object. 

The 'user' key in the JSON response refers to the $user object, which is serialized using the [UserResource] (#userResource) class. This enables customized formatting of user attributes, which I defined within the class, ensuring their inclusion in the JSON response.

The createToken() method generates a token for the authenticated user using Laravel Sanctum authentication. The plainTextToken property is then accessed on the generated token, which retrieves the plain text representation of the token

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
            'message' => 'username or password is incorrect.',
            'errors' => [
                'username' => ['username or password is incorrect.']
            ]
        ], 422);
    }
```
1-Using Api routes: 

routes\web.php:

```php
Route::get('observer/login', [ObserversAuthController::class, 'login'])->name('observer.login');
Route::post('observer/login', [ObserversAuthController::class, 'do_login'])->name('login');
Route::post('observer/logout', [ObserversAuthController::class, 'logout'])->name('observer.logout');
Route::get('user/login', [AuthController::class, 'login'])->name('user.login');
Route::post('user/login', [AuthController::class, 'do_login'])->name('user');
Route::post('user/logout', [AuthController::class, 'logout'])->name('user.logout');
```
app\Http\Controllers\ObserversAuthController.php:

The constructor, it sets up two middleware groups for specific controller methods.
These middleware configurations control the access privileges for different methods in the controller, allowing only guest users to use login-related methods and authenticated users with the'observer' role to access the logout method

```php
    public function __construct()
    {
        $this->middleware('ob_guest')->only('login','do_login');
        $this->middleware('ob_auth:observer')->only('logout');
    }
```

The login() function handles the logic for the login process in the context of observers.
First, it checks if there is already an authenticated observer user using the Auth::guard('observer')->user() method. If an observer user is already logged in, the function redirects them to the 'observer.home' route.
If there is no authenticated observer user, the function retrieves a collection of observers from the database, ordered by their names, using the orderBy query. This collection of observers is then passed to the 'observers.login' view.

```php
    public function login()
    {
        $observer = Auth::guard('observer')->user();
        if($observer)
            return redirect()->route('observer.home');
        $observers = Observer::orderBy('name')->get();
        return view('observers.login')->with("observers",$observers);
    }
```

The do_login() function handles the submission of the login form for observers.

The Hash::check() function is a method used to compare a plain text password with a hashed password. It takes two arguments: the plain text password ($request->password) and the hashed password($observer->password).
If the provided password does not match the stored password for the observer, it returns back to the login form with an error message indicating that the password is incorrect.

If the provided credentials are valid, the observer is logged in using the Auth::guard('observer')->login($observer) method, and the user is redirected to the 'observer.home' route.

```php
    public function do_login(Request $request)
    {
        $request->validate([
            'observer_id'       => ['required', 'exists:observers,id'],
            'password'          => ['required', 'string']
        ]);

        $observer = Observer::where('id', $request->observer_id)->first();

        if (!$observer->password) {
            return back()->withInput()->with('error',"المعلومات الشخصية للمراقب غير كاملة.\n يرجى إرسال صورة لوجهي الهوية الشخصية مع القسم والتوصيف الوظيفي والمرتبة العلمية على رقم واتساب التالي: <a href='https://wa.me/0985415539' target='_blank'>0985415539</a>");
        }

        if (!Hash::check($request->password, $observer->password)) {
            return back()->withInput()->with('error',' كلمة المرور غير صحيحة');
        }

        Auth::guard('observer')->login($observer);
        return redirect()->route('observer.home');
    }
```

app\Http\Controllers\AuthController.php:

This constructor sets up middleware groups to manage access privileges for specific controller methods. In this case, the 'ob_guest' middleware allows only guest users to access the 'login' and 'do_login' methods. On the other hand, the 'ob_auth:user' middleware only permits authenticated users with the 'user' role to access the 'logout' method.

```php
    public function __construct()
    {
        $this->middleware('ob_guest')->only('login','do_login');
        $this->middleware('ob_auth:user')->only('logout');
    }
```

The logout() function handles the logout process for users.

First, it calls the Auth::guard('user')->logout() method to log out the currently authenticated user from the 'user' guard. This effectively clears the user's authentication status and removes the associated token.

After logging out the user, the function redirects them to the 'home' route using redirect()->route('home').

```php
    public function logout()
    {
        Auth::guard('user')->logout();
        return redirect()->route('home');
    }
```

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

The `user-permissions` component includes the `UsersController.php` file, located in the `app\Http\Controllers\Api` directory. This file contains the following code:

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