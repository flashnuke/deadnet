from jnius import autoclass


def get_app_data_dir() -> str:
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    return context.getFilesDir().getAbsolutePath()
