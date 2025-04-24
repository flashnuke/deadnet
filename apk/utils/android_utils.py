from jnius import autoclass
 # todo handle exc here? or alreadt handled from outside?

def get_app_data_dir():
    context = autoclass('org.kivy.android.PythonActivity').mActivity
    return context.getFilesDir().getAbsolutePath()
